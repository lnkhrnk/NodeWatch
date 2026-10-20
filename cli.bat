@echo off
rem NodeWatch - admin console. Examples:
rem   cli.bat agents
rem   cli.bat --server 192.168.1.10 incidents
rem   cli.bat            (interactive mode)
chcp 65001 >nul
cd /d "%~dp0"
if "%MON_SECRET%"=="" set MON_SECRET=kursovoy-proekt-2026-secret
set PY=
where py >nul 2>nul && set "PY=py -3"
if not defined PY set "PY=python"
%PY% cli.py %*
