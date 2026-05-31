@echo off
chcp 65001 >nul 2>&1
echo ======================================================
echo   VSOS Guard v0.5.1 实机测试
echo ======================================================
echo.

cd /d "%~dp0..\.."
echo 当前目录: %CD%
echo.

python --version
if errorlevel 1 (
    echo [错误] Python未安装或不在PATH中
    pause
    exit /b 1
)

echo.
echo 正在运行测试...
echo.
python tests\run_v051_test.py

echo.
echo ======================================================
echo   测试完成
echo ======================================================
pause
