@echo off
chcp 65001 >nul
cd /d "%~dp0.."
set PY=
where py >nul 2>nul && set "PY=py -3"
if not defined PY set "PY=python"
%PY% -m unittest discover -s tests -v
pause
