@echo off
setlocal EnableExtensions
set "SCRIPT_PATH=%~dp0cursor-export-credential.py"

if not exist "%SCRIPT_PATH%" goto :missing_script

rem Prefer the Python Launcher, then fall back to python/python3.
where py >nul 2>&1
if not errorlevel 1 (
    py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,8) else 1)" >nul 2>&1
    if not errorlevel 1 goto :run_py
)

for %%P in (python python3) do (
    where %%P >nul 2>&1
    if not errorlevel 1 (
        "%%P" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,8) else 1)" >nul 2>&1
        if not errorlevel 1 (
            set "PYTHON_EXE=%%P"
            goto :run_python
        )
    )
)
goto :missing_python

:run_py
py -3 "%SCRIPT_PATH%" %*
set "EXIT_CODE=%ERRORLEVEL%"
endlocal & exit /b %EXIT_CODE%

:run_python
"%PYTHON_EXE%" "%SCRIPT_PATH%" %*
set "EXIT_CODE=%ERRORLEVEL%"
endlocal & exit /b %EXIT_CODE%

:missing_script
>&2 echo Cannot find cursor-export-credential.py next to this launcher.
endlocal & exit /b 1

:missing_python
>&2 echo Python 3.8 or newer was not found. Install Python and try again.
endlocal & exit /b 1
