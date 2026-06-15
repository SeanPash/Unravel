@echo off
REM ===========================================================================
REM Unravel - install the `unravel` command on Windows.
REM
REM This is the Windows counterpart to "make install" on Linux: it builds the
REM binary and puts it on your PATH so you can type `unravel` from any directory.
REM It needs NO administrator rights and NO PowerShell execution-policy change
REM (this is a batch file, and the single PowerShell call below is an inline
REM -Command, which execution policy does not restrict). From the engine folder:
REM
REM     cd engine
REM     install.cmd
REM
REM Then open a NEW terminal (so PATH refreshes) and run:  unravel --open
REM Pass "rebuild" to force a fresh build:  install.cmd rebuild
REM ===========================================================================
setlocal enableextensions
cd /d "%~dp0"

where go >nul 2>nul || (echo ERROR: Go was not found on your PATH. Install it from https://go.dev/dl/ ^(or run: winget install GoLang.Go^), then open a new terminal and try again.& exit /b 1)
where npm >nul 2>nul || (echo ERROR: Node/npm was not found on your PATH. Install it from https://nodejs.org/ ^(or run: winget install OpenJS.NodeJS.LTS^), then open a new terminal and try again.& exit /b 1)

if /i "%~1"=="rebuild" if exist "unravel.exe" del /q "unravel.exe"

if exist "unravel.exe" goto install

echo ==^> Building the UI ^(first run only; this can take a minute^)
call npm --prefix ..\ui install || (echo ERROR: npm install failed.& exit /b 1)
call npm --prefix ..\ui run build || (echo ERROR: UI build failed.& exit /b 1)
echo ==^> Embedding the UI into the binary
if exist "internal\api\static\assets" rd /s /q "internal\api\static\assets"
xcopy /E /I /Y "..\ui\dist\*" "internal\api\static\" >nul || (echo ERROR: copying the UI bundle failed.& exit /b 1)
echo ==^> Compiling unravel.exe
go build -o unravel.exe ".\cmd\engine" || (echo ERROR: go build failed.& exit /b 1)

:install
set "BINDIR=%LOCALAPPDATA%\Unravel"
if not exist "%BINDIR%" mkdir "%BINDIR%"
copy /Y "unravel.exe" "%BINDIR%\unravel.exe" >nul || (echo ERROR: could not copy unravel.exe to %BINDIR%.& exit /b 1)
echo ==^> Installed unravel.exe to %BINDIR%

REM Add BINDIR to the USER PATH (no admin) if it is not already there. Inline
REM -Command is not a .ps1 script, so PowerShell execution policy does not block
REM it; SetEnvironmentVariable on the User scope persists without setx's 1024-char
REM truncation risk.
powershell -NoProfile -Command "$d=$env:LOCALAPPDATA+'\Unravel'; $p=[Environment]::GetEnvironmentVariable('Path','User'); if($null -eq $p){$p=''}; if(($p -split ';') -notcontains $d){ if($p.TrimEnd(';')){$np=$p.TrimEnd(';')+';'+$d}else{$np=$d}; [Environment]::SetEnvironmentVariable('Path',$np,'User'); Write-Host ('==> Added '+$d+' to your user PATH.') } else { Write-Host '==> Already on your user PATH.' }"

echo.
echo Done. Open a NEW terminal (so PATH refreshes), then run:
echo     unravel --open      (replay demo, opens your browser)
echo     unravel             (interactive menu: Demo, or connect to Splunk)
endlocal
