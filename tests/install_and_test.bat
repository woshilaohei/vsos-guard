@echo off
chcp 65001 >nul 2>&1
echo ======================================================
echo   VSOS Guard v0.5.1 一键安装+测试
echo ======================================================
echo.

REM 检查Python
python --version >nul 2>&1
if errorlevel 1 (
    py --version >nul 2>&1
    if errorlevel 1 (
        echo [错误] 未找到Python，请先安装Python 3.8+
        pause
        exit /b 1
    )
    set PYTHON=py
) else (
    set PYTHON=python
)

echo [1/4] Python已就绪
echo.

REM 创建临时目录
set WORKDIR=%TEMP%\vsos_guard_test
if exist "%WORKDIR%" rmdir /s /q "%WORKDIR%"
mkdir "%WORKDIR%"
cd /d "%WORKDIR%"

echo [2/4] 从Gitee拉取代码...
git clone https://gitee.com/xiaoheivsos/vsos-guard.git
if errorlevel 1 (
    echo [错误] Git clone失败，请检查网络
    pause
    exit /b 1
)

echo.
echo [3/4] 安装vsos_guard包...
cd vsos-guard
%PYTHON% -m pip install -e . --quiet
if errorlevel 1 (
    echo [错误] pip install失败
    pause
    exit /b 1
)

echo.
echo [4/4] 运行v0.5.1全量测试...
%PYTHON% tests\run_v051_test.py

echo.
echo ======================================================
echo   测试完成！临时目录: %WORKDIR%
echo ======================================================
pause
