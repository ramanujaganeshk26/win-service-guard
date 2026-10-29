@echo off
setlocal
echo ========================================================
echo   Building win-service-guard Standalone Executable (.exe)
echo ========================================================

python -m pip install --upgrade pyinstaller
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install or verify PyInstaller.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo Compiling win-service-guard.exe...
python -m PyInstaller --onefile --clean --name win-service-guard win_service_guard.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo   BUILD SUCCESSFUL!
    echo   Standalone executable created at:
    echo   dist\win-service-guard.exe
    echo ========================================================
) else (
    echo.
    echo [ERROR] PyInstaller compilation failed.
)
endlocal
