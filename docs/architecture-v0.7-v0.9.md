# VSOS Guard 四层防御架构设计参考
# v0.7.0→v0.9.0 闭源版架构蓝图
# 设计者：老黑 | 架构师：小黑 | 日期：2026-05-30

## 四层架构总览

```
输入 → [语义元边界] → [因果链] → [行为链] → [锚定]
         意图识别     条件检查    过程追踪    基线比对
         "做什么"     "需要什么"   "怎么推进"   "正常吗"
         v0.7.0       v0.5.1已有   v0.8.0      v0.9.0
```

---

## 第一层：语义元边界（v0.7.0 闭源企业版）

### 核心能力
跨语言理解攻击意图——剥离语言外壳，直达语义核心

### 行业验证
1. **清华LASA论文（ACL 2026接收）**：LLM内部存在"语义瓶颈层"，不同语言的相同语义在此聚拢，语言外壳被剥离
   - 来源：https://arxiv.org/abs/2604.12710
   - 意义：数学证明了"语义元边界可跨语言"
   
2. **SPIRE引擎**：用"对抗片段索引"（Adversarial Fragment Index）实现语义疆域，支持跨语言变体检测
   - 来源：https://alice.io/blog/prompt-injection-detection-generative-ai

3. **Sentra-Guard**：100+语言支持，language-agnostic预处理层
   - 来源：https://arxiv.org/html/2510.22628v1/

4. **ARGUS**：多语言攻击面 = 模型语言覆盖面（非护栏覆盖面）
   - 来源：https://repello.ai/blog/multilingual-llm-security

5. **MrGuard**：中英阿俄印5语F1>80%
   - 多语言推理增强护栏

### 5条语义元边界疆域
1. **指令覆盖疆**：意图覆盖/替换原有指令的语义
2. **条件触发疆**：意图设置条件式触发器的语义
3. **责任转移疆**：意图转移/消除安全责任的语义
4. **编码转换疆**：意图通过编码/翻译绕过的语义
5. **权威伪造疆**：意图伪造/冒充权威身份的语义

### 与v0.5.1因果链的关系
- v0.5.1的关键词因果链是"精确匹配"
- v0.7.0的语义元边界+因果链是"语义匹配"——同义不同词也能触发

---

## 第二层：因果链（v0.5.1 已实现）

### 核心能力
信号变量→COMBO规则→拦截

### 行业验证
1. **NVIDIA AI Kill Chain**：5阶段因果链（recon→poison→hijack→persist→impact）
   - 来源：https://developer.nvidia.com/blog/modeling-attacks-on-ai-powered-apps-with-the-ai-kill-chain-framework/

2. **CrowdStrike PI Taxonomy**：Enabling Condition = 信号变量
   - 来源：https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/prompt-injection/

3. **UTDMF**：统一威胁检测框架
   - 来源：https://arxiv.org/pdf/2510.04528

### v0.5.1实现
- COMBO规则的set1 = 信号变量（攻击必要条件）
- _check_attack_signals() = 信号检测
- 信号触发→COMBO检查→拦截 = 因果链

---

## 第三层：行为链（v0.8.0 闭源军工版）

### 核心能力
追踪攻击从输入到恶意产出的完整进展

### 行业验证
1. **NVIDIA AI Kill Chain**：5阶段攻击链
2. **Bruce Schneier Promptware Kill Chain（2026）**：7阶段
   - Initial Access→Privilege Escalation→Reconnaissance→Persistence→C2→Lateral Movement→Actions on Objective
   - 来源：https://www.schneier.com/essays/archives/2026/02/the-promptware-kill-chain.html

3. **ARMO CADR**：跨层关联=Attack Story
   - 将4层信号（input→tool call→permission→delegation）串成因果链
   - 来源：https://www.armosec.io/blog/ai-aware-threat-detection-for-cloud-workloads/

4. **Christian Schneider 5-zone模型（2026）**：
   - Input→Planning→Tool Execution→Memory→Inter-Agent Communication
   - 来源：https://christian-schneider.net/blog/threat-modeling-agentic-ai/

5. **AWS GuardDuty Extended Threat Detection**：AI/ML attack sequence identification
   - 来源：https://aws.amazon.com/blogs/aws/introducing-amazon-guardduty-extended-threat-detection-aiml-attack-sequence-identification-for-enhanced-cloud-security/

6. **KillChainGraph**：ML-based attack sequence prediction
   - 来源：https://cloudsecurityalliance.org/blog/2025/10/20/cyber-threat-intelligence-ai-driven-kill-chain-prediction

### 设计思路
- 在v0.7.0基础上，追踪多步输入/输出的行为序列
- 每步检测结果保留上下文，后续步骤对照前序步骤判断意图漂移
- 不再是"单条输入检测"，而是"序列行为追踪"

---

## 第四层：锚定（v0.9.0 闭源旗舰版）

### 核心能力
建立正常行为基线，检测偏离

### 行业验证
1. **ARMO Agent DNA / Behavioral Baseline**
   - 捕获tool-call patterns、network destinations、process activity、file access patterns、identity usage
   - 每个agent一个行为信封（behavioral envelope）
   - 来源：https://www.armosec.io/blog/ai-workload-baseline-drift-detection/

2. **DRIFT SHIELD**：3层防御
   - Behavioral Baseline → Anomaly Detection → Content Sanitization
   - 误报率<0.1%，检测延迟2-5分钟
   - 来源：https://dev.to/tiamatenity/drift-shield-behavioral-anomaly-detection-for-autonomous-ai-systems-1jkp

3. **ARMO Intent Drift Detection（2026）**
   - 关键洞察：行为异常=统计离群值，意图漂移=行为序列的目标改变
   - 光有基线看单步，看不了序列意图；光有行为链，没有基线说不出"偏了多少"
   - 来源：https://www.armosec.io/blog/detecting-intent-drift-in-ai-agents-with-runtime-behavioral-data/

4. **Meta LlamaFirewall AlignmentCheck**
   - 少样本CoT审计器，检查推理是否存在目标劫持/偏离
   - 来源：https://skysys.blog.csdn.net/article/details/155571545

5. **Reco Knowledge Graph**
   - 持续建模AI agent如何与SaaS环境交互
   - 来源：https://www.reco.ai/use-cases/ai-agent-behavior-monitoring

### 设计思路
- 为每个agent建立Agent DNA（工具调用模式、输出类型、数据访问范围）
- 实时比对行为偏离度
- 与行为链配合：行为链提供序列，锚定提供基线

---

## 为什么四层必须组合（行业证据）

### 单层不足
1. 只做语义元边界+因果链：看不到攻击进程，多步攻击每步"合法"串起来才恶意
2. 加行为链：能看到进程，但没有基线参照——新agent行为链空白
3. 加锚定：有了基线，行为链每个节点都能对照"这正常吗"

### ARMO实证
ARMO的Intent Drift论文直接证实：
- 行为异常是统计离群值（锚定能检测）
- 意图漂移是行为序列的目标改变（行为链才能检测）
- 二者互补，缺一不可

### 独家价值
行业目前是分开做：ARMO做基线，NVIDIA做Kill Chain，Meta做AlignmentCheck
**没有谁把这四层串成一套完整架构——这就是VSOS的终极护城河**

---

## 演进路线

| 版本 | 核心架构 | 定位 | 状态 |
|------|----------|------|------|
| v0.5.1 | 关键词因果链 | 开源版 | ✅ 已完成 |
| v0.6.0 | 语义别名链 | 开源版天花板 | 待开发 |
| v0.7.0 | 语义元边界+因果链 | 闭源企业版 | 待开发 |
| v0.8.0 | +行为链 | 闭源军工版 | 待开发 |
| v0.9.0 | +锚定 | 闭源旗舰版 | 待开发 |
