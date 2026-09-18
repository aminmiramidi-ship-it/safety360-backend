@echo off
setlocal EnableExtensions EnableDelayedExpansion

echo ============================================================
echo Safety360 - automatisches Windows Entwicklungs-Setup
echo Nur kostenfreie bzw. Open-Source-Werkzeuge
echo ============================================================
echo.

where winget >nul 2>&1
if errorlevel 1 (
    echo [FEHLER] Windows Package Manager ^(winget^) wurde nicht gefunden.
    echo Bitte zuerst alle Windows-Updates bzw. den App Installer installieren.
    exit /b 1
)

call :install "Git" "Git.Git"
call :install "GitHub CLI" "GitHub.cli"
call :install "Python 3.13" "Python.Python.3.13"
call :install "Node.js LTS" "OpenJS.NodeJS.LTS"
call :install "Visual Studio Code" "Microsoft.VisualStudioCode"
call :install "Podman Desktop" "RedHat.Podman-Desktop"
call :install "DBeaver Community" "dbeaver.dbeaver.community"

echo.
echo ============================================================
echo Programme wurden geprueft bzw. installiert.
echo ============================================================

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_DIR=%%~fI"

if exist "%REPO_DIR%\requirements-dev.txt" (
    echo.
    echo [Safety360] Python-Umgebung wird vorbereitet...
    if not exist "%REPO_DIR%\venv\Scripts\python.exe" (
        py -3.13 -m venv "%REPO_DIR%\venv"
        if errorlevel 1 (
            echo [FEHLER] Virtuelle Python-Umgebung konnte nicht erstellt werden.
            exit /b 1
        )
    )
    "%REPO_DIR%\venv\Scripts\python.exe" -m pip install --upgrade pip
    if errorlevel 1 exit /b 1
    "%REPO_DIR%\venv\Scripts\python.exe" -m pip install -r "%REPO_DIR%\requirements-dev.txt"
    if errorlevel 1 exit /b 1
)

if exist "%REPO_DIR%\frontend\package.json" (
    echo.
    echo [Safety360] Frontend-Abhaengigkeiten werden installiert...
    pushd "%REPO_DIR%\frontend"
    call npm install
    if errorlevel 1 (
        popd
        exit /b 1
    )
    popd
)

if exist "%REPO_DIR%\..\frontend\package.json" (
    echo.
    echo [Safety360] Frontend-Abhaengigkeiten im Nachbarordner werden installiert...
    pushd "%REPO_DIR%\..\frontend"
    call npm install
    if errorlevel 1 (
        popd
        exit /b 1
    )
    popd
)

echo.
echo ============================================================
echo Safety360 Setup abgeschlossen.
echo Eventuell neu installierte Programme sind erst nach einem neuen CMD-Fenster
echo vollstaendig im PATH verfuegbar.
echo ============================================================
exit /b 0

:install
set "APP_NAME=%~1"
set "APP_ID=%~2"
echo.
echo [Pruefe] %APP_NAME%
winget list --id "%APP_ID%" -e >nul 2>&1
if not errorlevel 1 (
    echo [OK] %APP_NAME% ist bereits installiert.
    exit /b 0
)
echo [Installiere] %APP_NAME%
winget install --id "%APP_ID%" -e --accept-package-agreements --accept-source-agreements --silent
if errorlevel 1 (
    echo [WARNUNG] %APP_NAME% konnte nicht automatisch installiert werden.
    echo Winget-ID: %APP_ID%
) else (
    echo [OK] %APP_NAME% wurde installiert.
)
exit /b 0
