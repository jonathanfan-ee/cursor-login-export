@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto use_python
py -3 -c "import sys; sys.exit(sys.version_info < (3, 8))" >nul 2>nul
if errorlevel 1 goto use_python
py -3 cursor_session_transfer.py %*
goto finished

:use_python
where python >nul 2>nul
if errorlevel 1 goto missing
python -c "import sys; sys.exit(sys.version_info < (3, 8))" >nul 2>nul
if errorlevel 1 goto missing
python cursor_session_transfer.py %*
goto finished

:missing
echo 请先安装 Python 3.8 或更新版本：https://www.python.org/downloads/
echo 安装时勾选 Add python.exe to PATH，然后重新打开此文件。

:finished
echo.
pause
