@echo off
rem cmd.exe looks for commands in the current directory first. Start from the package folder,
rem never from a project folder that an agent can write to.
setlocal
set "NoDefaultCurrentDirectoryInExePath=1"
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto use_python
py -3 "%~dp0windows.py" %*
exit /b %errorlevel%
:use_python
python "%~dp0windows.py" %*
exit /b %errorlevel%
