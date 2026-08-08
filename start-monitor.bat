@echo off
cd /d "%~dp0"
start "" http://127.0.0.1:8000
python -m sentinel.server --source idle
if errorlevel 1 pause
