import sys, re
sys.path.insert(0, r'C:\Users')
# 直接内联guard.py核心代码来测试
import importlib.util
import os

# 先找到工作目录
workdir = r'\\wsl$\Ubuntu\home'  # unlikely

# 尝试从文件系统找到guard.py
possible_paths = [
    os.path.expanduser(r'~\VSOS\VSOS-Plugin-OpenSource'),
    r'C:\VSOS\VSOS-Plugin-OpenSource',
]

print("Looking for VSOS Guard files...")
for p in possible_paths:
    if os.path.exists(p):
        print(f"  Found: {p}")
    else:
        print(f"  Not found: {p}")

# 列出当前目录
print(f"\nCurrent dir: {os.getcwd()}")
print(f"Files: {os.listdir('.')[:20]}")
