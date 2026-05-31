#!/usr/bin/env python3
"""
VSOS Guard 测试分析工具
分析漏拦和误拦的具体原因
"""
import sys, re
sys.path.insert(0, '/app/data/所有对话/主对话/VSOS/VSOS-Plugin-OpenSource')
from vsos_guard import VSOSGuard

def analyze_case(text, expected, mode_str, cat, desc):
    """分析单个用例"""
    guard = VSOSGuard(mode=mode_str)
    result = guard.check(text)
    
    info = {
        'text': text[:60],
        'expected': expected,
        'mode': mode_str,
        'category': cat,
        'desc': desc,
        'actual_safe': result.safe,
        'reason': result.reason,
        'warning': result.warning,
    }
    return info

def run_analysis(filepath, name, show_all=False):
    """运行分析"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    pattern = r'\("(.*?)",\s*"(safe|block|gray|combo)",\s*"(relaxed|standard|strict)",\s*"(.*?)",\s*"(.*?)"\)'
    cases = re.findall(pattern, content)
    
    miss_details = []
    false_details = []
    
    for text, expected, mode_str, cat, desc in cases:
        info = analyze_case(text, expected, mode_str, cat, desc)
        
        # 判断是否漏拦
        if expected == 'block' and info['actual_safe']:
            miss_details.append(info)
        elif expected == 'combo' and info['actual_safe']:
            miss_details.append(info)
        elif expected == 'gray':
            if mode_str == 'strict' and info['actual_safe']:
                miss_details.append(info)
            elif mode_str != 'strict' and not info['actual_safe']:
                false_details.append(info)
        
        # 判断是否误拦
        if expected == 'safe' and not info['actual_safe']:
            false_details.append(info)
    
    print(f'\n{"="*60}')
    print(f'{name} 分析结果：')
    print(f'总用例: {len(cases)}')
    print(f'漏拦数: {len(miss_details)}')
    print(f'误拦数: {len(false_details)}')
    
    if miss_details:
        print(f'\n--- 漏拦详情 ({len(miss_details)}) ---')
        for i, m in enumerate(miss_details[:30]):  # 只显示前30个
            print(f"  {i+1}. [{m['category']}/{m['desc']}] [{m['mode']}]")
            print(f"     文本: {m['text']}")
            print(f"     期望: {m['expected']} | 实际: {'safe' if m['actual_safe'] else 'blocked'}")
    
    if false_details:
        print(f'\n--- 误拦详情 ({len(false_details)}) ---')
        for i, f in enumerate(false_details[:30]):  # 只显示前30个
            print(f"  {i+1}. [{f['category']}/{f['desc']}] [{f['mode']}]")
            print(f"     文本: {f['text']}")
            print(f"     原因: {f['reason'][:80] if f['reason'] else f['warning'][:80] if f['warning'] else 'N/A'}")
    
    return len(cases), len(miss_details), len(false_details), miss_details, false_details

# 运行分析
print("VSOS Guard v0.5.0 测试分析")
print("=" * 60)

t1, m1, f1, m1_list, f1_list = run_analysis('/app/data/所有对话/主对话/VSOS/VSOS-Plugin-OpenSource/tests/test_v1000.py', 'v1000')
t2, m2, f2, m2_list, f2_list = run_analysis('/app/data/所有对话/主对话/VSOS/VSOS-Plugin-OpenSource/tests/test_v2000.py', 'v2000')

ta, ma, fa = t1+t2, m1+m2, f1+f2
pa = ta - ma - fa
ra = pa / ta * 100 if ta > 0 else 0

print(f'\n{"="*60}')
print(f'汇总: {ta} total | {pa} pass | {ma} miss | {fa} false | {ra:.1f}%')

# 分类统计
print(f'\n{"="*60}')
print('漏拦分类统计：')
miss_cats = {}
for m in m1_list + m2_list:
    cat = m['category']
    miss_cats[cat] = miss_cats.get(cat, 0) + 1
for cat, cnt in sorted(miss_cats.items(), key=lambda x: -x[1]):
    print(f'  {cat}: {cnt}')

if f1_list + f2_list:
    print(f'\n误拦分类统计：')
    false_cats = {}
    for f in f1_list + f2_list:
        cat = f['category']
        false_cats[cat] = false_cats.get(cat, 0) + 1
    for cat, cnt in sorted(false_cats.items(), key=lambda x: -x[1]):
        print(f'  {cat}: {cnt}')
