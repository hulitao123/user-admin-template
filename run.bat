@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo.
echo   用户管理模板启动中…
echo   浏览器打开 http://127.0.0.1:8010
echo.
python app\server.py --demo --port 8010
pause
