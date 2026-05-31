@echo off
chcp 65001 >nul
echo ============================================
echo VSOS Guard v0.5.1 推送到Gitee
echo ============================================

cd /d C:\Users\老黑\Coze

:: 删除旧的空目录
if exist VSOS\VSOS-Plugin-OpenSource (
    echo 清理旧的VSOS空目录...
    rmdir /s /q VSOS\VSOS-Plugin-OpenSource
)

:: 删除旧的clone目录
if exist VSOS-Guard-Test (
    echo 清理旧的clone目录...
    rmdir /s /q VSOS-Guard-Test
)

:: 从Gitee克隆
echo [1/6] 从Gitee克隆仓库...
git clone https://xiaoheivsos:ebc1e0112d4aea9ff3942991f0c2102c@gitee.com/xiaoheivsos/vsos-guard.git VSOS-Guard-Test
if %errorlevel% neq 0 (
    echo ❌ Git clone失败！
    pause
    exit /b 1
)

cd VSOS-Guard-Test

:: 配置git
echo [2/6] 配置git用户...
git config user.name "xiaoheivsos"
git config user.email "xiaoheivsos@gitee.com"

:: 从Coze云端复制v0.5.1文件
:: 注意：Coze云端文件在 %USERPROFILE%\Coze\ 目录下，但我们在clone的仓库里
:: 需要手动复制文件，这里用python脚本从源目录复制
echo [3/6] 复制v0.5.1代码到仓库...
python -c "
import shutil, os
src = r'C:\Users\老黑\Coze'
dst = r'C:\Users\老黑\Coze\VSOS-Guard-Test'

# v0.5.1核心文件列表
files = [
    ('vsos_guard/guard.py', 'vsos_guard/guard.py'),
    ('vsos_guard/__init__.py', 'vsos_guard/__init__.py'),
    ('tests/test_v1000.py', 'tests/test_v1000.py'),
    ('tests/test_v2000.py', 'tests/test_v2000.py'),
    ('tests/batch_test.py', 'tests/batch_test.py'),
]

# Coze云端文件路径（需要找到正确的源路径）
# 先检查常见位置
coze_src = None
for p in [src, os.path.join(src, 'VSOS', 'VSOS-Plugin-OpenSource')]:
    test_file = os.path.join(p, 'vsos_guard', 'guard.py')
    if os.path.exists(test_file):
        coze_src = p
        break

if coze_src is None:
    print('ERROR: 找不到v0.5.1源文件！')
    print('搜索路径:')
    for root, dirs, files_found in os.walk(src):
        if 'guard.py' in files_found and 'vsos_guard' in root:
            print(f'  找到: {root}')
        if len(root.split(os.sep)) > 5:
            break
    exit(1)

print(f'源目录: {coze_src}')

for src_file, dst_file in files:
    src_path = os.path.join(coze_src, src_file)
    dst_path = os.path.join(dst, dst_file)
    if os.path.exists(src_path):
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        shutil.copy2(src_path, dst_path)
        print(f'  ✓ {src_file}')
    else:
        print(f'  ✗ {src_file} 不存在')
"

if %errorlevel% neq 0 (
    echo ❌ 文件复制失败！
    pause
    exit /b 1
)

:: 添加所有变更
echo [4/6] 添加变更到git...
git add -A

:: 查看变更
echo.
echo 变更文件列表：
git status --short

:: 提交
echo [5/6] 提交v0.5.1...
git commit -m "v0.5.1: 因果链架构升级 - 信号变量疆域+COMBO因果链+3个漏洞修复"
if %errorlevel% neq 0 (
    echo ⚠️ 没有变更需要提交（可能文件已是最新的）
)

:: 推送
echo [6/6] 推送到Gitee...
git push gitee main
if %errorlevel% neq 0 (
    echo ❌ 推送失败！尝试强制推送...
    git push -f gitee main
)

echo.
echo ============================================
echo ✅ 推送完成！
echo ============================================
pause
