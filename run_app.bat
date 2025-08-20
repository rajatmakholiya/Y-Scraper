@echo off
echo Starting the web application...

REM Start the backend server in a new window.
start "Backend Server" cmd /k "python backend/app.py"

REM Start a simple web server for the frontend in a new window.
start "Frontend Server" cmd /k "python -m http.server 8000 --directory frontend"

echo.
echo Waiting a moment for the servers to initialize...
timeout /t 2 /nobreak > nul

echo Opening the application in your default web browser...
start http://localhost:8000

echo.
pause