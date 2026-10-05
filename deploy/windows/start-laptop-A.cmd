@echo off
rem Laptop A on demo day: dashboard + normal-traffic hub + the "Laptop A" immune node, and
rem Ollama for "Explain incident" (Gemma 4) when it is installed.
rem Double-click it (Python 3.10+ and config\nodes.json needed). Close the window to stop.
cd /d "%~dp0\..\.."
title Hive - Laptop A

rem Ollama: from OLLAMA_DIR (its portable folder; models in OLLAMA_DIR\models), else PATH.
if not defined OLLAMA_DIR set "OLLAMA_DIR=G:\Tools\ollama"
set "OLLAMA_EXE="
if exist "%OLLAMA_DIR%\bin\ollama.exe" set "OLLAMA_EXE=%OLLAMA_DIR%\bin\ollama.exe"
if not defined OLLAMA_EXE for %%x in (ollama.exe) do if not "%%~$PATH:x"=="" set "OLLAMA_EXE=%%~$PATH:x"
if not defined OLLAMA_EXE (
  echo Ollama not found: "Explain incident" will use its built-in summary.
) else (
  tasklist /nh /fi "imagename eq ollama.exe" | findstr /i "ollama.exe" >nul || (
    if exist "%OLLAMA_DIR%\models" set "OLLAMA_MODELS=%OLLAMA_DIR%\models"
    set "OLLAMA_HOST=127.0.0.1:11434"
    set "OLLAMA_KEEP_ALIVE=-1"
    rem keep compiled CUDA kernels, so Gemma loads in seconds instead of minutes
    set "CUDA_CACHE_MAXSIZE=4294967296"
    start "Hive - Ollama" /min "%OLLAMA_EXE%" serve
  )
)

rem Windows may leave a hotspot without internet for another saved network: say so up front.
python tools\demo_wifi.py status

start "" /min cmd /c "timeout /t 4 >nul & start http://localhost:8080"
python tools\hive_up.py dashboard node:lapA
pause
