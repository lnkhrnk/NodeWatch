@echo off
rem NodeWatch - central server (HTTP 8080, UDP 9999, TCP 9998)
chcp 65001 >nul
cd /d "%~dp0"

rem ---- shared secret: must be the SAME on the server and on every agent ----
if "%MON_SECRET%"=="" set MON_SECRET=kursovoy-proekt-2026-secret

call :find_python || goto :end
echo Checking dependencies (psutil)...
%PY% -m pip install --disable-pip-version-check -q -r requirements.txt
echo.
echo Panel link with token will be printed below. Open it in a browser (PC, laptop or phone).
echo Stop the server: Ctrl+C
echo.
%PY% server.py %*
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
