@echo off
call "%~dp0cursor-export-credential.cmd" --show-token %*
set "EXIT_CODE=%ERRORLEVEL%"
if not defined CURSOR_EXPORT_NO_PAUSE pause
exit /b %EXIT_CODE%
