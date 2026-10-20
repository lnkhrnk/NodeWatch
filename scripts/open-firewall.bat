@echo off
rem Opens NodeWatch ports in Windows Firewall. Run on the SERVER computer
rem with right click -> "Run as administrator".
net session >nul 2>&1
if errorlevel 1 (
  echo Please run this file as administrator.
  pause
  exit /b 1
)
netsh advfirewall firewall delete rule name="NodeWatch HTTP 8080" >nul 2>&1
netsh advfirewall firewall delete rule name="NodeWatch TCP 9998" >nul 2>&1
netsh advfirewall firewall delete rule name="NodeWatch UDP 9999" >nul 2>&1
netsh advfirewall firewall add rule name="NodeWatch HTTP 8080" dir=in action=allow protocol=TCP localport=8080
netsh advfirewall firewall add rule name="NodeWatch TCP 9998" dir=in action=allow protocol=TCP localport=9998
netsh advfirewall firewall add rule name="NodeWatch UDP 9999" dir=in action=allow protocol=UDP localport=9999
echo Done: ports 8080/TCP, 9998/TCP, 9999/UDP are open.
pause
