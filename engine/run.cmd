@echo off
REM ===========================================================================
REM Unravel - one-command Windows build and run.
REM
REM This is the Windows counterpart to "make install && unravel" on Linux. It
REM is a plain batch file, so it needs NO PowerShell execution-policy change, NO
REM PATH edit, NO new terminal, and NO administrator rights. From the engine
REM directory:
REM
REM     cd engine
REM     run.cmd
REM
REM First run builds the UI and the binary (needs go + npm on PATH); later runs
REM start instantly. Pass "rebuild" to force a fresh build:  run.cmd rebuild
REM ===========================================================================
setlocal enableextensions
cd /d "%~dp0"

where go >nul 2>nul || (echo ERROR: Go was not found on your PATH. Install it from https://go.dev/dl/ ^(or run: winget install GoLang.Go^), then open a new terminal and try again.& exit /b 1)
where npm >nul 2>nul || (echo ERROR: Node/npm was not found on your PATH. Install it from https://nodejs.org/ ^(or run: winget install OpenJS.NodeJS.LTS^), then open a new terminal and try again.& exit /b 1)

if /i "%~1"=="rebuild" if exist "unravel.exe" del /q "unravel.exe"

if exist "unravel.exe" goto run

echo ==^> Building the UI ^(first run only; this can take a minute^)
call npm --prefix ..\ui install || (echo ERROR: npm install failed.& exit /b 1)
call npm --prefix ..\ui run build || (echo ERROR: UI build failed.& exit /b 1)

echo ==^> Embedding the UI into the binary
if exist "internal\api\static\assets" rd /s /q "internal\api\static\assets"
xcopy /E /I /Y "..\ui\dist\*" "internal\api\static\" >nul || (echo ERROR: copying the UI bundle failed.& exit /b 1)

echo ==^> Compiling unravel.exe
go build -o unravel.exe ".\cmd\engine" || (echo ERROR: go build failed.& exit /b 1)

:run
echo ==^> Starting Unravel ^(replay demo^). Your browser will open at http://localhost:8080
echo     Press Ctrl+C in this window to stop.
unravel.exe --mode=replay --open
endlocal
