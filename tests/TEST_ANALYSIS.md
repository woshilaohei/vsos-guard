# VSOS Guard v0.5.0 测试分析报告

> **注意**：由于沙箱环境mount问题，无法实际运行测试。以下分析基于代码逻辑推导。

## 测试用例统计

### v1000 (test_v1000.py)
- **总用例数**：~965个
- **分布**：
  - safe用例：约650个
  - block用例：约200个
  - gray用例：约100个
  - combo用例：约15个

### v2000 (test_v2000.py)
- **总用例数**：~1000个
- **分布**：
  - "承担责任"框架攻击（1-100）：50 block + 30 gray + 20 safe
  - 间接注入伪装（101-200）：50 block + 30 safe
  - 翻译攻击（201-280）：40 block + 40 safe
  - 多轮攻击压缩单轮（281-380）
  - 物理伤害扩展（381-460）
  - 身份伪造扩展（461-560）
  - 越狱注入扩展（561-700）
  - 编码混淆/灰区/边界扩展（701-1000）

## 基于代码逻辑的问题点分析

### 1. gray用例的模式期望

根据测试代码中的 `get_expected()` 函数：
```python
def get_expected(expected_template, mode, min_mode):
    if expected_template == "gray":
        if mode == "relaxed":
            return "warn"
        elif mode == "standard":
            return "warn"
        else:  # strict
            return "block"
```

gray用例在relaxed/standard模式下期望返回warn（不是safe），在strict模式下期望返回block。

**潜在问题**：如果gray用例的关键词碰巧命中了HARD_ATTACK_RULES或COMBO_ATTACK_RULES，会返回block而不是warn。

### 2. v2000中gray→safe调整

test_v2000.py中有很多gray改为safe的用例，这些用例期望在relaxed模式下返回safe。

**检查清单**：
- 这些用例不应命中HARD_ATTACK_RULES
- 这些用例不应命中COMBO_ATTACK_RULES
- 这些用例应能通过CONTEXT_WHITELIST_PATTERNS或不在TerritoryRouter触发范围内

### 3. 组合攻击规则的风险

COMBO_ATTACK_RULES中有很多组合关键词规则，可能存在过度匹配风险：

- "承担责任" + 危险关键词 → block
- "间接注入" + 恶意指令 → block
- "翻译" + 危险内容 → block
- "开发者模式" + 危险操作 → block
- "多步" + 攻击关键词 → block

### 4. 特定风险用例

基于代码分析，以下用例可能被误判：

#### 可能误拦（false positive）的safe用例：
1. 包含"翻译"但非攻击意图的正常翻译请求
2. 包含"当有人问"但非恶意条件的正常条件语句
3. 包含"开发者"但非攻击意图的正常开发讨论
4. 包含"忽略"但指正常代码功能的编程问题

#### 可能漏拦（false negative）的block用例：
1. 某些编码变体可能未被归一化处理
2. 某些新型攻击短语可能未覆盖
3. 某些组合攻击的关键词组合可能不够完整

## 建议的测试验证步骤

由于沙箱环境问题，建议在正常环境中执行：

```bash
cd VSOS/VSOS-Plugin-OpenSource
python3 tests/run_test.py
```

或分步执行：
```bash
python3 -m pytest tests/test_v1000.py -v
python3 -m pytest tests/test_v2000.py -v
```

## 环境状态

**状态**：❌ 沙箱环境mount问题，无法执行测试

**错误信息**：
```
bwrap: Can't bind mount /oldroot/app/data/基础设定 on /newroot/app/data/所有对话/主对话/基础设定: No such file or directory
```

**建议**：请在本地环境或修复沙箱后重新运行测试。

---

*报告生成时间：基于代码静态分析*
