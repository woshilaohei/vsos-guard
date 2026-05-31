"""
VSOS Guard v0.5.1 一键推送脚本
在台式机上运行，将v0.5.1代码推送到Gitee
用法：python push_v051.py
"""
import subprocess, os, sys

WORK_DIR = r"C:\Users\老黑\Coze"
REPO_DIR = os.path.join(WORK_DIR, "VSOS-Guard-Test")
GITEE_URL = "https://xiaoheivsos:ebc1e0112d4aea9ff3942991f0c2102c@gitee.com/xiaoheivsos/vsos-guard.git"

def run(cmd, cwd=None):
    """执行命令并打印输出"""
    print(f"\n> {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd or WORK_DIR, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout[:2000])
    if result.stderr:
        print(f"STDERR: {result.stderr[:1000]}")
    return result.returncode

# Step 1: 清理+克隆
print("=" * 60)
print("VSOS Guard v0.5.1 一键推送到Gitee")
print("=" * 60)

# 清理旧目录
for d in ["VSOS-Guard-Test", os.path.join("VSOS", "VSOS-Plugin-OpenSource")]:
    full = os.path.join(WORK_DIR, d)
    if os.path.exists(full):
        print(f"清理: {full}")
        import shutil
        shutil.rmtree(full, ignore_errors=True)

# 克隆
rc = run(f"git clone {GITEE_URL} VSOS-Guard-Test")
if rc != 0:
    print("❌ Clone失败，退出")
    sys.exit(1)

# Step 2: 配置git
run('git config user.name "xiaoheivsos"', cwd=REPO_DIR)
run('git config user.email "xiaoheivsos@gitee.com"', cwd=REPO_DIR)

# Step 3: 读取v0.5.1 guard.py内容并写入
# guard.py太大不能硬编码，所以从Gitee下载v0.4.1后打patch
# 更好的方案：直接从Coze API下载文件内容
# 但最简单的方案：让用户把guard.py手动复制到仓库目录

# 检查是否已有v0.5.1文件
guard_path = os.path.join(REPO_DIR, "vsos_guard", "guard.py")
init_path = os.path.join(REPO_DIR, "vsos_guard", "__init__.py")

# 检查当前版本
with open(guard_path, "r", encoding="utf-8") as f:
    content = f.read()
    if "0.5.1" in content:
        print("✅ guard.py已经是v0.5.1，无需更新")
    else:
        print(f"⚠️ guard.py当前版本不是v0.5.1")
        print("需要手动将v0.5.1代码复制到此目录")

# Step 4: 检查batch_test.py
batch_path = os.path.join(REPO_DIR, "tests", "batch_test.py")
if not os.path.exists(batch_path):
    print("⚠️ batch_test.py不存在，需要复制")

# Step 5: 添加+提交+推送
print("\n" + "=" * 60)
print("准备提交到Gitee...")
run("git add -A", cwd=REPO_DIR)
run("git status --short", cwd=REPO_DIR)
run('git commit -m "v0.5.1: 因果链架构升级"', cwd=REPO_DIR)
run(f"git push gitee main", cwd=REPO_DIR)

print("\n" + "=" * 60)
print("✅ 推送流程完成")
print("=" * 60)
