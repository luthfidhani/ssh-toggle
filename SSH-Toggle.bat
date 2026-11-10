@echo off
rem Launcher for SSH-Toggle.ps1. Extra arguments are passed through, e.g.:
rem   SSH-Toggle.bat -AllowedRemote 192.168.1.12
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0SSH-Toggle.ps1" %*
