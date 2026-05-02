@echo off
title VAXINX Lab Launcher

set PORT=8000

echo 🔁 Rebuilding test lab...
timeout /t 1 >nul
python create_test_lab.py

echo.
echo 🛡️ Running scanner...
python scanner.py

echo.
echo 🌐 Starting local server on %PORT%...
start "" cmd /k python -m http.server %PORT%

timeout /t 2 >nul

echo 🚀 Opening dashboard...
start "" http://localhost:%PORT%/index.html

echo.
echo ✅ SYSTEM READY
pause