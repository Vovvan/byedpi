@echo off
setlocal
cd /d "%~dp0"
title ByeDPI - YouTube
echo ByeDPI SOCKS5: 127.0.0.1:1080
echo Set your browser to use this SOCKS5 proxy.
echo Press Ctrl+C to stop.
echo.
ciadpi.exe -i 127.0.0.1 -p 1080 --tlsrec 1+s --disorder 1+s
echo.
echo ByeDPI stopped.
pause
