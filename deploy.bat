@echo off
title VAXINX Git Deploy
color 0A

echo ================================
echo   VAXINX AUTO DEPLOY SYSTEM
echo ================================
echo.

:: Check if inside a git repo
git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    echo ERROR: Not a git repository!
    pause
    exit /b
)

:: Ask commit message
set /p msg=Enter commit message:
if "%msg%"=="" set msg=update: auto deploy

echo.
echo Adding files...
git add .

echo.
echo Committing...
git commit -m "%msg%"
if errorlevel 1 (
    echo Nothing to commit or commit failed.
    pause
    exit /b
)

echo.
echo Pushing to GitHub...
git push

echo.
echo Opening live dashboard...
start https://regislara-byte.github.io/vaxinx-stoplight-code/

echo.
echo ================================
echo     DEPLOY COMPLETE
echo ================================
pause