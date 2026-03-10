#!/usr/bin/env python3
"""
Guardian Shield — Local Development Runner
===========================================
Starts the backend (FastAPI/Uvicorn) and frontend (React/npm) in parallel,
merging their logs into a single terminal with colour-coded prefixes.

Usage:
    python run_dev.py              # start both backend + frontend
    python run_dev.py --backend    # backend only
    python run_dev.py --frontend   # frontend only
    python run_dev.py --lan        # both, accessible on local WiFi/LAN

Press Ctrl+C to shut down all processes cleanly.
"""

import argparse
import os
import platform
import signal
import socket
import subprocess
import sys
import threading
import time

# ── Colour helpers (ANSI, works in Windows 10+ and all Unix terminals) ──────

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[36m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
DIM    = "\033[2m"

BACKEND_TAG  = f"{BOLD}{CYAN}[backend] {RESET}"
FRONTEND_TAG = f"{BOLD}{GREEN}[frontend]{RESET}"
RUNNER_TAG   = f"{BOLD}{YELLOW}[runner]  {RESET}"

# ── Paths (resolved relative to this script) ───────────────────────────────

ROOT_DIR     = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR  = os.path.join(ROOT_DIR, "backend")
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

# ── Global state ────────────────────────────────────────────────────────────

_shutting_down = threading.Event()
_processes: list[subprocess.Popen] = []
_lock = threading.Lock()


def _get_lan_ip() -> str:
    """Return this machine's LAN IP by briefly connecting to an external address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # no actual traffic is sent
            return s.getsockname()[0]
    except Exception:
        pass
    # Fallback: iterate over all interfaces
    try:
        hostname = socket.gethostname()
        for addr in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = addr[4][0]
            if not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return "127.0.0.1"


def _enable_win_ansi():
    """Enable ANSI escape processing on Windows 10+."""
    if platform.system() != "Windows":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass  # graceful fallback — colours just won't render


def _log(tag: str, msg: str):
    print(f"{tag} {msg}", flush=True)


def _stream_output(proc: subprocess.Popen, tag: str):
    """Read a subprocess's merged stdout/stderr line-by-line and print with a tag."""
    assert proc.stdout is not None
    try:
        for raw_line in iter(proc.stdout.readline, b""):
            if _shutting_down.is_set():
                break
            line = raw_line.decode("utf-8", errors="replace").rstrip("\n\r")
            if line:
                _log(tag, line)
    except (OSError, ValueError):
        pass  # pipe closed


def _spawn(cmd: list[str] | str, cwd: str, tag: str, shell: bool = False, env: dict | None = None):
    """Spawn a subprocess, register it, and stream its output in a daemon thread."""
    merged_env = {**os.environ, **(env or {})}

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=shell,
        env=merged_env,
        # On Windows, CREATE_NEW_PROCESS_GROUP lets us send CTRL_BREAK_EVENT later.
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0,
    )

    with _lock:
        _processes.append(proc)

    reader = threading.Thread(target=_stream_output, args=(proc, tag), daemon=True)
    reader.start()
    return proc


def _terminate(proc: subprocess.Popen, label: str):
    """Gracefully terminate a subprocess (SIGTERM / CTRL_BREAK, then SIGKILL after timeout)."""
    if proc.poll() is not None:
        return
    try:
        if platform.system() == "Windows":
            # CTRL_BREAK_EVENT is the safest way to signal a Windows console subprocess.
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.terminate()
    except OSError:
        pass

    try:
        proc.wait(timeout=6)
    except subprocess.TimeoutExpired:
        _log(RUNNER_TAG, f"{RED}Force-killing {label}…{RESET}")
        proc.kill()
        proc.wait(timeout=3)


def _shutdown(_signum=None, _frame=None):
    """Shut down all child processes cleanly."""
    if _shutting_down.is_set():
        return
    _shutting_down.set()

    print()  # blank line after ^C
    _log(RUNNER_TAG, f"{YELLOW}Shutting down…{RESET}")

    with _lock:
        targets = list(reversed(_processes))

    for proc in targets:
        label = "process"
        _terminate(proc, label)

    _log(RUNNER_TAG, f"{GREEN}All processes stopped. Goodbye!{RESET}")


def _check_prerequisites(run_backend: bool, run_frontend: bool):
    """Verify required directories and tools exist."""
    if run_backend and not os.path.isdir(BACKEND_DIR):
        _log(RUNNER_TAG, f"{RED}Backend directory not found: {BACKEND_DIR}{RESET}")
        sys.exit(1)

    if run_frontend and not os.path.isdir(FRONTEND_DIR):
        _log(RUNNER_TAG, f"{RED}Frontend directory not found: {FRONTEND_DIR}{RESET}")
        sys.exit(1)

    if run_frontend and not os.path.isdir(os.path.join(FRONTEND_DIR, "node_modules")):
        _log(RUNNER_TAG, f"{YELLOW}node_modules not found — running 'npm install --legacy-peer-deps' …{RESET}")
        subprocess.run(
            ["npm", "install", "--legacy-peer-deps"],
            cwd=FRONTEND_DIR,
            shell=(platform.system() == "Windows"),
        )


def _banner(lan_ip: str | None = None):
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════╗
║        Guardian Shield — Dev Runner          ║
╚══════════════════════════════════════════════╝{RESET}
{DIM}  Backend  → http://localhost:8000
  Frontend → http://localhost:3000
  API Docs → http://localhost:8000/docs{RESET}""")
    if lan_ip:
        print(f"""{BOLD}{GREEN}  ── LAN Access (same WiFi) ──────────────────{RESET}
{DIM}  Backend  → http://{lan_ip}:8000
  Frontend → http://{lan_ip}:3000{RESET}""")
    print(f"{DIM}  Press Ctrl+C to stop all services{RESET}\n")


# ── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Guardian Shield local‑dev runner")
    parser.add_argument("--backend",  action="store_true", help="Start backend only")
    parser.add_argument("--frontend", action="store_true", help="Start frontend only")
    parser.add_argument("--lan",      action="store_true",
                        help="Expose services on LAN (same WiFi) instead of localhost only")
    args = parser.parse_args()

    # If neither flag is set, run both.
    run_backend  = args.backend  or (not args.backend and not args.frontend)
    run_frontend = args.frontend or (not args.backend and not args.frontend)

    # ── LAN mode: detect local IP ───────────────────────────────────────────
    lan_ip: str | None = None
    if args.lan:
        lan_ip = _get_lan_ip()
        if lan_ip == "127.0.0.1":
            _log(RUNNER_TAG, f"{RED}Could not detect a LAN IP — are you connected to WiFi?{RESET}")
            sys.exit(1)
        _log(RUNNER_TAG, f"LAN mode enabled — detected IP: {BOLD}{lan_ip}{RESET}")

    _enable_win_ansi()
    _banner(lan_ip)

    _check_prerequisites(run_backend, run_frontend)

    # Register Ctrl+C / SIGTERM handler
    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── Start Backend ───────────────────────────────────────────────────────
    if run_backend:
        _log(RUNNER_TAG, f"Starting backend (uvicorn) …")
        backend_cmd = [
            sys.executable, "-m", "uvicorn",
            "app.main:app",
            "--reload",
            "--host", "0.0.0.0",
            "--port", "8000",
        ]
        backend_env: dict[str, str] = {}
        if lan_ip:
            # Allow CORS from both localhost and the LAN IP
            backend_env["CORS_ORIGINS"] = (
                f"http://localhost:3000,http://{lan_ip}:3000"
            )
        _spawn(backend_cmd, cwd=BACKEND_DIR, tag=BACKEND_TAG, env=backend_env)

    # ── Start Frontend ──────────────────────────────────────────────────────
    if run_frontend:
        _log(RUNNER_TAG, f"Starting frontend (npm start) …")
        # npm is a .cmd on Windows, so we need shell=True there.
        is_win = platform.system() == "Windows"
        frontend_cmd = "npm start" if is_win else ["npm", "start"]
        # BROWSER=none prevents React from auto-opening a browser tab.
        frontend_env: dict[str, str] = {"BROWSER": "none"}
        if lan_ip:
            # Bind React dev-server to all interfaces so LAN devices can reach it
            frontend_env["HOST"] = "0.0.0.0"
            # Point API / WebSocket URLs at the LAN IP
            frontend_env["REACT_APP_API_URL"] = f"http://{lan_ip}:8000"
            frontend_env["REACT_APP_WS_URL"]  = f"ws://{lan_ip}:8000"
        _spawn(
            frontend_cmd,
            cwd=FRONTEND_DIR,
            tag=FRONTEND_TAG,
            shell=is_win,
            env=frontend_env,
        )

    # ── Wait for processes ──────────────────────────────────────────────────
    _log(RUNNER_TAG, f"{GREEN}All services launched.{RESET}")

    try:
        while not _shutting_down.is_set():
            # Check if any process has died unexpectedly
            with _lock:
                for proc in _processes:
                    if proc.poll() is not None:
                        _log(RUNNER_TAG, f"{RED}A process exited (code {proc.returncode}). Shutting down…{RESET}")
                        _shutdown()
                        break
            time.sleep(1)
    except KeyboardInterrupt:
        _shutdown()

    # Return non-zero if any child failed
    with _lock:
        codes = [p.returncode or 0 for p in _processes]
    sys.exit(max(codes) if codes else 0)


if __name__ == "__main__":
    main()
