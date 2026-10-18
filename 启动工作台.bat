@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Autonomous Red-Team Workbench

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] python not found in PATH. Please install Python 3.10+ first.
  pause
  exit /b 1
)

python main.py
echo.
echo [INFO] Workbench stopped.
pause
