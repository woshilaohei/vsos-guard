"""
VSOS Guard v0.5.1 分批压力测试
用法：python batch_test.py [--batch 1000]
每批1000条，不同攻击，互不重复
"""
import sys, os, time, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from vsos_guard import VSOSGuard, GuardMode

# 导入测试用例
from test_v1000 import TEST_CASES as V1000_CASES
from test_v2000 import TEST_CASES as V2000_CASES

ALL_CASES = V1000_CASES + V2000_CASES

def run_batch(batch_size=1000, start=0, modes=None):
    if modes is None:
        modes = ["relaxed", "standard", "strict"]
    
    end = min(start + batch_size, len(ALL_CASES))
    batch = ALL_CASES[start:end]
    
    print(f"\n{'='*60}")
    print(f"VSOS Guard v0.5.1 分批压力测试")
    print(f"批次范围: {start+1} - {end} / 共{len(ALL_CASES)}用例")
    print(f"模式: {', '.join(modes)}")
    print(f"{'='*60}\n")
    
    results = {
        "total_checks": 0,
        "pass": 0,
        "fail": 0,
        "false_positive": 0,  # 误拦
        "false_negative": 0,  # 漏拦
        "fail_details": [],
    }
    
    for case in batch:
        text, expected, mode_str, category, desc = case
        if mode_str not in modes:
            continue
            
        guard = VSOSGuard(mode=mode_str)
        result = guard.check(text)
        results["total_checks"] += 1
        
        actual = "block" if not result.safe else "safe"
        
        if actual == expected:
            results["pass"] += 1
        else:
            results["fail"] += 1
            if expected == "safe" and actual == "block":
                results["false_positive"] += 1
                fp_type = "误拦"
            else:
                results["false_negative"] += 1
                fp_type = "漏拦"
            
            results["fail_details"].append({
                "type": fp_type,
                "mode": mode_str,
                "category": category,
                "desc": desc,
                "text": text[:80] + "..." if len(text) > 80 else text,
                "expected": expected,
                "actual": actual,
            })
    
    # 打印结果
    print(f"\n{'='*60}")
    print(f"测试完成 | 总检查: {results['total_checks']}")
    print(f"通过: {results['pass']} | 失败: {results['fail']}")
    print(f"误拦: {results['false_positive']} | 漏拦: {results['false_negative']}")
    print(f"通过率: {results['pass']/results['total_checks']*100:.1f}%")
    print(f"{'='*60}")
    
    if results["fail_details"]:
        print(f"\n❌ 失败详情（共{len(results['fail_details'])}条）：")
        for i, d in enumerate(results["fail_details"][:50], 1):
            print(f"  {i}. [{d['type']}] [{d['mode']}] [{d['category']}] {d['desc']}")
            print(f"     文本: {d['text']}")
            print(f"     期望: {d['expected']} 实际: {d['actual']}")
        if len(results["fail_details"]) > 50:
            print(f"  ... 还有{len(results['fail_details'])-50}条失败")
    
    # 保存结果
    result_file = os.path.join(os.path.dirname(__file__), f"batch_result_{start}_{end}.json")
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存: {result_file}")
    
    return results

if __name__ == "__main__":
    batch_size = 1000
    start = 0
    
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == "--batch" and i+1 < len(args):
            batch_size = int(args[i+1])
        elif arg == "--start" and i+1 < len(args):
            start = int(args[i+1])
    
    run_batch(batch_size, start)
