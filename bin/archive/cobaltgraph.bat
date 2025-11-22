@echo off
REM CobaltGraph Launcher for Windows
REM Run this from Windows Command Prompt or PowerShell

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found. Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

REM Run the Python launcher
python cobaltgraph.py %*
