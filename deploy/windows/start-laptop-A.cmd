@echo off
rem Laptop A on demo day: dashboard + normal-traffic hub + the "Laptop A" immune node.
rem Double-click it (Python 3.10+ and config\nodes.json needed). Close the window to stop.
cd /d "%~dp0\..\.."
title Hive - Laptop A
start "" /min cmd /c "timeout /t 4 >nul & start http://localhost:8080"
python tools\hive_up.py dashboard node:lapA
pause
