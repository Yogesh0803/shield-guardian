@echo off
cd /d "c:\Users\hp\Desktop\COLLEGE 1\Capgemini\guardian-shield"
echo ============================================
echo   Running as Administrator
echo ============================================
echo.
python -m ml.tests.smoke_test
echo.
echo ============================================
python -m ml.tests.test_packet_filter
echo.
echo ============================================
echo Done.
pause
