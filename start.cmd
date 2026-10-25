@echo off
rem cmd.exe looks for commands in the current directory first. Start from the package folder,
rem never from a project folder that an agent can write to.
setlocal
set "NoDefaultCurrentDirectoryInExePath=1"
cd /d "%~dp0"
if exist "%~dp0.venv\Scripts\python.exe" goto use_venv
if exist "%~dp0venv\Scripts\python.exe" goto use_venv_alt
where py >nul 2>nul
if errorlevel 1 goto use_python
py -3 "%~dp0windows.py" %*
exit /b %errorlevel%
:use_python
python "%~dp0windows.py" %*
exit /b %errorlevel%
:use_venv
"%~dp0.venv\Scripts\python.exe" "%~dp0windows.py" %*
exit /b %errorlevel%
:use_venv_alt
"%~dp0venv\Scripts\python.exe" "%~dp0windows.py" %*
exit /b %errorlevel%
