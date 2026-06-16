@echo off
title SRP Node — Sovereign Root Protocol
setlocal enabledelayedexpansion

set "SRP_ROOT=%~dp0"
cd /d "%SRP_ROOT%"

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] Python not found. Install Python 3.11+ and ensure it is on your PATH.
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set "PY_VER=%%v"
echo [NODE] Python %PY_VER%
echo [NODE] SRP Root: %SRP_ROOT%
echo.

:: Create venv and instruct user to install deps
if not exist ".venv\Scripts\python.exe" (
    if exist "requirements.txt" (
        echo [NODE] Creating virtual environment...
        python -m venv .venv
        if !errorlevel! equ 0 (
            echo [NODE] Virtual environment created
            echo [NODE] Run the following to install dependencies:
            echo       .venv\Scripts\pip install -r requirements.txt
            echo.
        )
    )
)

:: Use venv Python if available
if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else (
    set "PY=python"
)

:: Check for certificates
if not exist "cluster\certs\ca.crt" (
    echo [NODE] Certificates not found — generating...
    "%PY%" cluster\generate_certs.py >nul 2>&1
    if !errorlevel! equ 0 (
        echo [NODE] Certificates generated
    ) else (
        echo [WARN] Certificate generation skipped — run generate_certs.py manually
    )
)

:: Route command — pass through to srp-node.py if provided
set "FIRST=%1"
if not "%FIRST%"=="" (
    echo %FIRST%|findstr /r "^[1-7]$" >nul
    if !errorlevel! equ 0 (
        set "CMD=%FIRST%"
        goto :menu_exec
    )
    echo [NODE] Running: srp-node.py %*
    "%PY%" srp-node.py %*
    exit /b !errorlevel!
)

:menu
cls
echo.
echo  ============================================================
echo    SOVEREIGN ROOT PROTOCOL (SRP) — Node Controller
echo    Version 2026.4.2
echo  ============================================================
echo.
echo   1. Interactive Setup Wizard     (srp-node init)
echo   2. Start Services               (srp-node start)
echo   3. Health Check                 (srp-node status)
echo   4. Stop Services                (srp-node stop)
echo   5. Open Config Wizard (HTML)    (wizard.html)
echo   6. Run Local Tests              (srp_local_test.py)
echo   7. Exit
echo.
echo   Or type a command directly, e.g.: start --skip-loader
echo.
set "CMD="
set /p "CMD=Select [1-7]: "

:menu_exec
if "%CMD%"=="" echo [NODE] No input & goto :menu_end
if "%CMD%"=="1" "%PY%" srp-node.py init     & goto :menu_end
if "%CMD%"=="2" "%PY%" srp-node.py start    & goto :menu_end
if "%CMD%"=="3" "%PY%" srp-node.py status   & goto :menu_end
if "%CMD%"=="4" "%PY%" srp-node.py stop     & goto :menu_end
if "%CMD%"=="5" start "" "frontend\wizard.html" & goto :menu_end
if "%CMD%"=="6" "%PY%" scripts\srp_local_test.py & goto :menu_end
if "%CMD%"=="7" exit /b 0

:: If not a menu number, pass as raw command to srp-node.py
echo [NODE] Running: srp-node.py %CMD%
"%PY%" srp-node.py %CMD%

:menu_end
echo.
pause
goto :menu
