@echo off
REM ============================================================================
REM  dut_listen.bat  --  run this ON THE WINDOWS DUT (double-click or run it).
REM  Starts the ncat control listener the Mac collector talks to. Leave it open.
REM
REM  Before running:
REM    * make sure wlan is connected to the AP (that's the traffic we capture)
REM    * allow the port through the firewall (PowerShell as Admin, once):
REM        New-NetFirewallRule -DisplayName ncat9999 -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9999
REM
REM  Then on the Mac:
REM    python3 data/real/collect_ncat.py --dut-host <THIS-PC-IP>
REM ============================================================================
setlocal
set PORT=9999
echo Starting ncat listener on port %PORT%  (leave this window open; Ctrl-C to stop)
echo This PC's IPs (use the one the Mac can reach as --dut-host):
ipconfig | findstr /R /C:"IPv4"
echo.
"%~dp0ncat.exe" -k -l %PORT% --sh-exec "powershell -NoProfile -Command -"
