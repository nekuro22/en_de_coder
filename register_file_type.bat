@echo off
REM Registry script to register .encrypted file type with Verschluesselungs-Tool
REM Run this as Administrator after building the EXE

REM Find the EXE path - assumes it's in the current directory or dist folder
setlocal enabledelayedexpansion

REM Try to find the EXE
if exist "Verschluesselungs-Tool.exe" (
    set "EXE_PATH=%cd%\Verschluesselungs-Tool.exe"
) else if exist "dist\Verschluesselungs-Tool.exe" (
    set "EXE_PATH=%cd%\dist\Verschluesselungs-Tool.exe"
) else (
    echo ERROR: Verschluesselungs-Tool.exe not found!
    echo Please make sure the EXE has been built using PyInstaller.
    pause
    exit /b 1
)

echo Registering .encrypted file type with:
echo !EXE_PATH!
echo.

REM Create the file type association
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.encrypted\UserChoice" /f >nul 2>&1

REM Register the .encrypted extension
reg add "HKCU\Software\Classes\.encrypted" /ve /d "EncryptedFile" /f
reg add "HKCU\Software\Classes\.encrypted" /v "Content Type" /d "application/octet-stream" /f

REM Create the file type handler
reg add "HKCU\Software\Classes\EncryptedFile" /ve /d "Encrypted File (Verschlüsselungs-Tool)" /f
reg add "HKCU\Software\Classes\EncryptedFile\DefaultIcon" /ve /d "!EXE_PATH!,0" /f

REM Set the open command
reg add "HKCU\Software\Classes\EncryptedFile\shell" /f
reg add "HKCU\Software\Classes\EncryptedFile\shell\open" /f
reg add "HKCU\Software\Classes\EncryptedFile\shell\open\command" /ve /d "\"!EXE_PATH!\" \"%%1\"" /f

REM Alternative method - Direct to .encrypted extension (Windows 10+)
reg add "HKCU\Software\Classes\.encrypted\shell\open\command" /ve /d "\"!EXE_PATH!\" \"%%1\"" /f

REM Update file association
assoc .encrypted=EncryptedFile

echo.
echo SUCCESS: .encrypted files are now associated with Verschluesselungs-Tool!
echo.
echo You can now:
echo 1. Right-click any .encrypted file
echo 2. Select "Open with" or "Properties"
echo 3. Choose "Verschluesselungs-Tool" as the default program
echo.
pause
