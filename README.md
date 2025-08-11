# DDH-Based Private Intersection-Sum Protocol Implementation

## 项目概述

本项目实现了基于**Diffie-Hellman (DDH) 假设**的私有交集求和协议（Private Intersection-Sum with Cardinality），该协议源自Google的研究论文，用于隐私保护的广告转化率计算和密码泄露检查（如Google Password Checkup）。协议允许两个参与方（P1 和 P2）在不泄露私有数据集的情况下，计算**交集的大小（Cardinality）**和**交集元素的关联值求和（Sum）**，确保只揭示聚合统计信息。

该实现使用**Python**语言，依赖于**椭圆曲线加密**和**加法同态加密（Paillier方案）**，适用于**半诚实安全模型**。项目旨在演示协议的核心逻辑，可扩展到实际部署场景，如密码检查服务。

### 特性
- 支持任意规模的输入数据集（受内存限制）。
- 实现协议的完整轮次，包括Setup、Round 1-3 和输出。
- 使用 **NIST prime256v1 椭圆曲线**和 **Paillier 加密**。
- 包含单元测试和示例用法。

### 依赖
- Python 3.8+
- 库：`cryptography` (用于椭圆曲线和哈希)，`gmpy2` (用于Paillier实现)

安装依赖：
```
pip install cryptography gmpy2
```

---

## 协议数学推导

协议基于Decisional Diffie-Hellman (DDH) 假设和加法同态加密。假设群 $G$ 为素数阶群，生成元 $g$，哈希函数 $H: U \to G$ 为随机预言机。

### 输入
- P1: 集合 $V = \{v_i\}_{i=1}^{m_1}$, $v_i \in U$。
- P2: 集合 $W = \{(w_j, t_j)\}_{j=1}^{m_2}$, $w_j \in U$, $t_j \in \mathbb{Z}^+$。

### 输出
- 双方: 交集大小 $C = |\{j : w_j \in V\}|$。
- P2: 交集求和 $S = \sum_{j: w_j \in V} t_j$。

### 协议步骤

1.  **Setup**:
    - 每个方选择随机指数 $k_1, k_2 \in [1, |G|]$。
    - P2 生成同态加密密钥 $(pk, sk)$，发送 $pk$ 给 P1。

2.  **Round 1 (P1)**:
    - 计算 $\{H(v_i)^{k_1}\}_{i=1}^{m_1}$，打乱顺序发送给 P2。
    - 数学依据: $H(v_i)^{k_1}$ 是单层伪随机掩码 (DDH下不可区分)。

3.  **Round 2 (P2)**:
    - 对收到的 $\{H(v_i)^{k_1}\}$ 指数化: $H(v_i)^{k_1 k_2}$，打乱作为 $Z$ 发送回 P1。
    - 对自身输入: $\{(H(w_j)^{k_2}, \text{AEnc}(pk, t_j))\}_{j=1}^{m_2}$，打乱发送给 P1。
    - 推导: 双层掩码 $H(v_i)^{k_1 k_2} = H(w_j)^{k_1 k_2}$ iff $v_i = w_j$ (哈希相等)。

4.  **Round 3 (P1)**:
    - 对收到的 $H(w_j)^{k_2}$ 指数化: $H(w_j)^{k_1 k_2}$。
    - 交集: $J = \{j : H(w_j)^{k_1 k_2} \in Z\}$。
    - 同态求和: $\text{AEnc}(pk, S_J) = \sum_{j \in J} \text{AEnc}(pk, t_j) = \text{AEnc}(pk, \sum_{j \in J} t_j)$。
    - 刷新: $\text{ARefresh}(\text{AEnc}(pk, S_J))$，发送给 P2。
    - 推导: 同态属性确保 $\text{Dec}(sk, \sum \text{AEnc}(t_j)) = \sum t_j$，刷新隐藏求和过程 (统计不可区分)。

5.  **输出 (P2)**:
    - 解密得到 $S_J = S$。
    - $C = |J|$ (P1 已知，可共享)。

### 正确性
若 $v_i = w_j$，则 $H(v_i) = H(w_j)$，故 $H(v_i)^{k_1 k_2} = H(w_j)^{k_1 k_2}$。哈希碰撞概率 negl(λ)。

### 安全性
在半诚实模型下，视图可模拟 (Theorem 1 & 2 [1])。DDH 确保掩码伪随机；打乱隐藏对应；HE 确保聚合隐私。

---

## 用法示例

```python
from protocol import Party1, Party2

# P1 输入
V = ['user1', 'user2', 'user3']

# P2 输入
W = [('user2', 100), ('user4', 200), ('user3', 300)]

p1 = Party1(V)
p2 = Party2(W)

# 执行协议
round1_data = p1.round1()
round2_data, Z = p2.round2(round1_data)
encrypted_sum = p1.round3(round2_data, Z)
sum_result, cardinality = p2.output(encrypted_sum)

print(f"交集求和: {sum_result}, 大小: {cardinality}")  # 输出: 400, 2
```

---

### 实现细节
- `paillier.py`: Paillier 加法同态加密实现。
- `ddh.py`: 椭圆曲线群操作。
- `protocol.py`: 协议核心类 (`Party1`, `Party2`)。
- 测试: `python -m unittest test_protocol.py`。

## 参考文献
[1] Mihaela Ion et al. "On Deploying Secure Computing: Private Intersection-Sum-with-Cardinality." Google LLC, 2019.
