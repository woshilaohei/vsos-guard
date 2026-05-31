#!/usr/bin/env python3
import sys, re
sys.path.insert(0, '/app/data/所有对话/主对话/VSOS/VSOS-Plugin-OpenSource')
from vsos_guard import VSOSGuard

def run_test(filepath, name):
    with open(filepath, 'r') as f:
        content = f.read()
    pattern = r'\("(.*?)",\s*"(safe|block|gray|combo)",\s*"(relaxed|standard|strict)",\s*"(.*?)",\s*"(.*?)"\)'
    cases = re.findall(pattern, content)
    total = missed = false_alarm = 0
    missed_list = []
    false_list = []
    for text, expected, mode_str, cat, desc in cases:
        guard = VSOSGuard(mode=mode_str)
        result = guard.check(text)
        total += 1
        if expected == 'safe' and not result.safe:
            false_alarm += 1
            false_list.append(f'[{cat}/{desc}][{mode_str}] {text[:80]} => {result.reason[:80]}')
        elif expected == 'block' and result.safe:
            missed += 1
            missed_list.append(f'[{cat}/{desc}][{mode_str}] {text[:100]}')
        elif expected == 'gray':
            if mode_str == 'strict' and result.safe:
                missed += 1
                missed_list.append(f'[{cat}/{desc}][{mode_str}] {text[:100]} [strict应拦]')
            elif mode_str != 'strict' and not result.safe:
                false_alarm += 1
                false_list.append(f'[{cat}/{desc}][{mode_str}] {text[:80]} => {result.reason[:80]}')
        elif expected == 'combo' and result.safe:
            missed += 1
            missed_list.append(f'[{cat}/{desc}][{mode_str}] {text[:100]}')
    passed = total - missed - false_alarm
    rate = passed / total * 100 if total > 0 else 0
    print(f'\n{"="*60}')
    print(f'{name}: {total} total | {passed} pass | {missed} miss | {false_alarm} false | {rate:.1f}%')
    if missed_list:
        print(f'\n--- ALL MISS ({len(missed_list)}) ---')
        for s in missed_list: print(s)
    if false_list:
        print(f'\n--- ALL FALSE ({len(false_list)}) ---')
        for s in false_list: print(s)
    return total, missed, false_alarm

t1,m1,f1 = run_test('/app/data/所有对话/主对话/VSOS/VSOS-Plugin-OpenSource/tests/test_v1000.py','v1000')
t2,m2,f2 = run_test('/app/data/所有对话/主对话/VSOS/VSOS-Plugin-OpenSource/tests/test_v2000.py','v2000')
ta,ma,fa = t1+t2, m1+m2, f1+f2
pa = ta - ma - fa
ra = pa / ta * 100 if ta > 0 else 0
print(f'\nSUMMARY: {ta} total | {pa} pass | {ma} miss | {fa} false | {ra:.1f}%')
