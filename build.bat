@echo off
echo ============================================
echo  CoolTR — Build EXE
echo ============================================
echo.

REM Install pyinstaller if not present
pip show pyinstaller >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing PyInstaller...
    pip install pyinstaller
    echo.
)

echo Building CoolTR.exe...
pyinstaller cooltr.spec --clean --noconfirm

echo.
if exist "dist\CoolTR.exe" (
    echo Build succeeded!
    echo Output: dist\CoolTR.exe
) else (
    echo Build FAILED. Check output above for errors.
)
echo.
pause
