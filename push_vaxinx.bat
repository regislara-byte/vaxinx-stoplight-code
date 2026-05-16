@echo off
title VAXINX Push System v3

color 0A

echo.
echo ===============================
echo    VAXINX PUSH PIPELINE
echo ===============================
echo.

git status

echo.
set /p commitmsg=Enter commit message: 

echo.
echo Adding files...
git add .

echo.
echo Committing...
git commit -m "%commitmsg%"

echo.
echo Pushing to GitHub...
git push

echo.
echo ===============================
echo        PUSH COMPLETE
echo ===============================
echo.

start "" "https://github.com/regislara-byte/vaxinx-ai-scanner"
start "" "https://github.com/regislara-byte/vaxinx-ai-scanner/vaxinx-stoplight-code/dashboard/index.html"

pause