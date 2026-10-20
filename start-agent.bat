@echo off
rem NodeWatch - agent. Usage: start-agent.bat [SERVER_IP] [NODE_NAME]
chcp 65001 >nul
cd /d "%~dp0"

rem ---- IP address of the computer where start-server.bat is running ----
set SERVER=127.0.0.1
if not "%~1"=="" set SERVER=%~1

rem ---- shared secret: must be the SAME as on the server ----
if "%MON_SECRET%"=="" set MON_SECRET=kursovoy-proekt-2026-secret

set NODEARG=
if not "%~2"=="" set NODEARG=--node %~2

call :find_python || goto :end
%PY% -m pip install --disable-pip-version-check -q -r requirements.txt
echo Agent sends metrics to %SERVER%. Stop: Ctrl+C
echo.
%PY% agent.py --host %SERVER% %NODEARG%
goto :end

:find_python
set PY=
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
  echo Python 3 not found. Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during installation.
  exit /b 1
)
exit /b 0

:end
pause
