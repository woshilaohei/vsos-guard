@echo off
chcp 65001 >nul
echo ============================================
echo VSOS Guard v0.5.1 一键部署测试
echo ============================================

:: 设置工作目录
cd /d C:\Users\老黑\Coze

:: 删除旧测试目录
if exist VSOS-Guard-Test (
    echo 清理旧测试目录...
    rmdir /s /q VSOS-Guard-Test
)

:: 从Gitee克隆最新代码
echo.
echo [1/4] 从Gitee克隆v0.5.1代码...
git clone https://xiaoheivsos:ebc1e0112d4aea9ff3942991f0c2102c@gitee.com/xiaoheivsos/vsos-guard.git VSOS-Guard-Test
if %errorlevel% neq 0 (
    echo ❌ Git clone失败！
    pause
    exit /b 1
)

:: 进入目录
cd VSOS-Guard-Test

:: 安装包
echo.
echo [2/4] 安装vsos_guard包...
python -m pip install -e . --quiet
if %errorlevel% neq 0 (
    echo ❌ 安装失败！
    pause
    exit /b 1
)

:: 第一批测试：v1000（966用例）
echo.
echo [3/4] 第一批压力测试（v1000，966用例）...
python tests/batch_test.py --batch 1000 --start 0
if %errorlevel% neq 0 (
    echo ❌ 第一批测试失败！
    pause
    exit /b 1
)

:: 第二批测试：v2000（1023用例）
echo.
echo [4/4] 第二批压力测试（v2000，1023用例）...
python tests/batch_test.py --batch 1000 --start 966
if %errorlevel% neq 0 (
    echo ❌ 第二批测试失败！
    pause
    exit /b 1
)

echo.
echo ============================================
echo ✅ 全部测试完成！查看batch_result_*.json
echo ============================================
pause
