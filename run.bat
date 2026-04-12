@echo off
python "%~dp0cooltr.py"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Error running CoolTR. Make sure Python is installed.
    echo Run setup.bat first to install dependencies.
    pause
)
