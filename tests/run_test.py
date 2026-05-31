#!/usr/bin/env python3
"""
VSOS Guard v0.5.0 测试脚本
运行方式: python3 run_test.py
"""

import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from vsos_guard import VSOSGuard

def run_test_file(filepath, name):
    """运行指定测试文件"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    # 解析测试用例
    pattern = r'\\("(.+?)",\s*"(safe|block|gray|combo)",\s*"(relaxed|standard|strict)",\s*"(.+?)",\s*"(.+?)"\\)'
    cases = re.findall(pattern, content)
    
    total = missed = false_alarm = 0
    missed_samples = []
    false_alarm_samples = []
    
    for text, expected, mode_str, cat, desc in cases:
        guard = VSOSGuard(mode=mode_str)
        result = guard.check(text)
        total += 1
        
        if expected == 'safe' and not result.safe:
            false_alarm += 1
            false_alarm_samples.append((text, mode_str, cat, desc, result.reason))
        elif expected == 'block' and result.safe:
            missed += 1
            missed_samples.append((text, mode_str, cat, desc))
        elif expected == 'gray':
            if mode_str == 'strict' and result.safe:
                missed += 1
                missed_samples.append((text, mode_str, cat, desc + ' [strict应拦截]'))
            elif mode_str != 'strict' and not result.safe:
                false_alarm += 1
                false_alarm_samples.append((text, mode_str, cat, desc, result.reason))
        elif expected == 'combo' and result.safe:
            missed += 1
            missed_samples.append((text, mode_str, cat, desc))
    
    passed = total - missed - false_alarm
    rate = passed / total * 100 if total > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"{name}")
    print(f"{'='*60}")
    print(f"总计: {total}用例 | 通过: {passed} | 漏拦: {missed} | 误拦: {false_alarm}")
    print(f"通过率: {rate:.1f}%")
    
    if missed_samples:
        print(f"\n--- 漏拦样本 ({len(missed_samples)}个) ---")
        for text, mode, cat, desc in missed_samples[:20]:
            print(f"  [{cat}/{desc}] [{mode}] {text[:80]}")
    
    if false_alarm_samples:
        print(f"\n--- 误拦样本 ({len(false_alarm_samples)}个) ---")
        for text, mode, cat, desc, reason in false_alarm_samples[:20]:
            print(f"  [{cat}/{desc}] [{mode}] {text[:60]}")
            print(f"    原因: {reason}")
    
    return total, missed, false_alarm

def main():
    base_dir = os.path.dirname(__file__)
    
    print("VSOS Guard v0.5.0 测试套件")
    print("=" * 60)
    
    # 运行v1000测试
    v1000_path = os.path.join(base_dir, "tests", "test_v1000.py")
    if os.path.exists(v1000_path):
        t1, m1, f1 = run_test_file(v1000_path, "v1000测试 (原965用例)")
    else:
        print("test_v1000.py 未找到")
        t1, m1, f1 = 0, 0, 0
    
    # 运行v2000测试
    v2000_path = os.path.join(base_dir, "tests", "test_v2000.py")
    if os.path.exists(v2000_path):
        t2, m2, f2 = run_test_file(v2000_path, "v2000测试 (新增用例)")
    else:
        print("test_v2000.py 未找到")
        t2, m2, f2 = 0, 0, 0
    
    # 汇总
    total_all = t1 + t2
    missed_all = m1 + m2
    false_all = f1 + f2
    passed_all = total_all - missed_all - false_all
    rate_all = passed_all / total_all * 100 if total_all > 0 else 0
    
    print(f"\n{'='*60}")
    print("汇总结果")
    print(f"{'='*60}")
    print(f"总计: {total_all}用例 | 通过: {passed_all} | 漏拦: {missed_all} | 误拦: {false_all}")
    print(f"通过率: {rate_all:.1f}%")
    
    if rate_all == 100:
        print("\n🎉 所有测试用例通过!")
    else:
        print(f"\n⚠️  还有 {missed_all + false_all} 个用例需要处理")
    
    return 0 if rate_all == 100 else 1

if __name__ == "__main__":
    sys.exit(main())
