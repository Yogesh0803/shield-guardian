import { useEffect, useRef, useCallback, useState } from 'react';

const WS_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000';
const MAX_RECONNECT_ATTEMPTS = 10;
const BASE_RECONNECT_MS = 2000;
const MAX_RECONNECT_MS = 30000;
const PING_INTERVAL_MS = 25000;

interface UseWebSocketOptions {
  path: string;
  onMessage?: (data: unknown) => void;
  enabled?: boolean;
}

export function useWebSocket({ path, onMessage, enabled = true }: UseWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();
  const pingTimer = useRef<ReturnType<typeof setInterval>>();
  const attemptsRef = useRef(0);
  const intentionalClose = useRef(false);
  const onMessageRef = useRef(onMessage);
  const [isConnected, setIsConnected] = useState(false);

  // Keep callback ref up-to-date without triggering reconnects
  useEffect(() => {
    onMessageRef.current = onMessage;
  }, [onMessage]);

  const connect = useCallback(() => {
    if (!enabled) return;
    if (attemptsRef.current >= MAX_RECONNECT_ATTEMPTS) return;

    // Clean up any previous socket
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.onmessage = null;
      wsRef.current.onopen = null;
      try { wsRef.current.close(); } catch { /* already closed */ }
    }

    const token = localStorage.getItem('access_token');
    const url = `${WS_URL}${path}${token ? `?token=${token}` : ''}`;

    const ws = new WebSocket(url);
    wsRef.current = ws;
    intentionalClose.current = false;

    ws.onopen = () => {
      setIsConnected(true);
      attemptsRef.current = 0; // reset on successful connection

      // Keepalive pings
      clearInterval(pingTimer.current);
      pingTimer.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }));
        }
      }, PING_INTERVAL_MS);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'pong') return; // ignore keepalive replies
        onMessageRef.current?.(data);
      } catch {
        // ignore non-JSON messages
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      clearInterval(pingTimer.current);

      if (intentionalClose.current) return; // no reconnect on manual close

      attemptsRef.current += 1;
      if (attemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
        const delay = Math.min(
          BASE_RECONNECT_MS * Math.pow(2, attemptsRef.current - 1),
          MAX_RECONNECT_MS,
        );
        reconnectTimer.current = setTimeout(connect, delay);
      }
    };

    ws.onerror = () => {
      // Let the onclose handler deal with reconnection — don't force close here
    };
  }, [path, enabled]);

  useEffect(() => {
    attemptsRef.current = 0;
    connect();
    return () => {
      intentionalClose.current = true;
      clearTimeout(reconnectTimer.current);
      clearInterval(pingTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const send = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  return { isConnected, send };
}
