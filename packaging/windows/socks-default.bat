@echo off
setlocal
cd /d "%~dp0"
title ByeDPI - SOCKS5
echo ByeDPI SOCKS5: 127.0.0.1:1080
echo Press Ctrl+C to stop.
echo.
ciadpi.exe -i 127.0.0.1 -p 1080
echo.
echo ByeDPI stopped.
pause
