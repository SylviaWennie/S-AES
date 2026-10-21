# 开发手册

## 结构与取舍

Python 标准库实现算法和本地 HTTP 服务，原生 HTML / CSS / JavaScript 与 SVG 实现 GUI。算法是纯函数，命令行、网页、测试共用同一套业务模块；网页只负责组织请求和绘图，**页面里没有第二套密码算法**，图解里的每个数字都来自后端返回的真实运算结果。

为了在一个人完成时也能做交叉测试，项目里有三份结构不同的独立实现：A（`core`）为主实现；B（`peer`）、C（`matrix`）不导入 A 的算法和常量，只共享最底层的输入输出工具。

| 文件 | 职责 |
| --- | --- |
| `saes/gf16.py` | GF(2⁴) 乘法、求逆、多项式长除法与乘法推导文字 |
| `saes/formats.py` | 16 位数据 / 密钥的解析（二进制或十六进制）与格式化 |
| `saes/core.py` | **实现 A**：S 盒、行移位、列混淆、密钥扩展、加解密流程（`ENCRYPT_PLAN` / `DECRYPT_PLAN`） |
| `saes/peer.py` | **实现 B**：全程 0/1 字符串，列混淆用“乘 x”位运算 |
| `saes/matrix.py` | **实现 C**：GF(2⁴) 多项式矩阵，S 盒由求逆 + 仿射变换构造，解密用教材 D.5 的等价逆算法 |
| `saes/implementations.py` | 把三种实现统一成 `(整数分组, 整数密钥) → 整数` 的接口 |
| `saes/modes.py` | 第 3 关字符串分组与填充、第 5 关 CBC |
| `saes/multiple.py` | 第 4 关双重 / 三重加密、中间相遇攻击、穷举时间估算 |
| `saes/experiments.py` | 中间相遇示例与结果整理、CBC 篡改实验 |
| `saes/exchange.py` | 交叉测试交换文件（JSON / 三列文本）的生成与核验 |
| `saes/visualization.py` | 13 步图解数据、组内 / 组间模拟、原理速查表 |
| `saes/selftest.py` | 五关自检（网页“一键闯关”与命令行共用） |
| `saes/server.py` | 只监听本机的 HTTP 服务、输入解析、JSON 路由 |
| `saes/__main__.py` | `python -m saes` 命令行（复用 `server.dispatch`） |
| `web/` | 页面：`index.html`、`style.css`、`visuals.css`；`common.js`（DOM / 接口工具）、`visuals.js`（图 D.1/D.2/D.3/D.5 与播放器）、`figures.js`（计算细节面板、传输图、计算链、CBC 链）、`charts.js`（漏斗图、状态条）、`app.js`（页面逻辑） |
| `tests/` | `textbook.py`（教材原表，测试专用）与各类测试 |
| `scripts/` | `generate_report.py`（真实实验与测试结果文档）、`check_ui.mjs`（浏览器端到端检查与截图）、`lib/cdp.mjs`（零依赖 DevTools 协议客户端）、`shot.mjs`（开发辅助截图） |
| `reports/` | 保存的实验数据与检查结果（JSON） |
| `examples/` | 交换文件、三列向量、中间相遇示例 |
| `docs/` | 文档与截图 |

## 数据表示

16 位值是 Python `int`（0–65535）；最高位是 b₀。半字节按 `N0 = value >> 12`、`N1 = (value >> 8) & 15`、`N2 = (value >> 4) & 15`、`N3 = value & 15` 取出，状态矩阵 `[[N0, N2], [N1, N3]]`（按列排列）。详见[算法说明](algorithm.md)。

加解密流程以数据描述，计算和图解共用：

```python
# core.py：每步 = (操作名, 使用的轮密钥序号或 None)
ENCRYPT_PLAN = (("add_key", 0), ("substitute", None), ("shift_rows", None), ("mix_columns", None),
                ("add_key", 1), ("substitute", None), ("shift_rows", None), ("add_key", 2))
DECRYPT_PLAN = (("add_key", 2), ("inv_shift_rows", None), ("inv_substitute", None), ("add_key", 1),
                ("inv_mix_columns", None), ("inv_shift_rows", None), ("inv_substitute", None), ("add_key", 0))
```

`run_plan(plan, block, keys)` 用 `functools.reduce` 依次应用各步；`trace_block` 记录每步之后的状态，图解的 `before` / `after` 就是它们，所以图和计算不可能分叉（测试里也逐项核对）。

## Python 接口

```python
from saes import encrypt_block, decrypt_block
from saes.core import expand_key, round_keys, trace_block
from saes.implementations import IMPLEMENTATIONS            # {"A": ..., "B": ..., "C": ...}
from saes import modes, multiple, exchange
from saes.experiments import mitm_example, mitm_experiment, cbc_tamper_experiment
from saes.visualization import visual_trace, simulate_group, simulate_peers
from saes.selftest import run_all

assert encrypt_block(0x6F6B, 0xA73B) == 0x0738
assert decrypt_block(0x0738, 0xA73B) == 0x6F6B
assert IMPLEMENTATIONS["C"].encrypt(0x6F6B, 0xA73B) == 0x0738      # 三种实现可互换
blocks = modes.ecb_encrypt("Hello".encode(), 0xA73B)                 # 字符串（2 字节一组）
assert multiple.double_decrypt(multiple.double_encrypt(0x6F6B, 0x2D55A73B), 0x2D55A73B) == 0x6F6B
```

| 函数 | 输入 / 返回 |
| --- | --- |
| `core.encrypt_block(plaintext, key)` / `decrypt_block(ciphertext, key)` | 0–65535 的整数 → 整数；拒绝布尔值、负数、越界、非整数（`ValueError`） |
| `core.expand_key(key)` | 6 个 8 位字 `(w0..w5)` |
| `core.round_keys(key)` | `(K0, K1, K2)`，各 16 位 |
| `core.trace_block(block, key, decrypt=False)` | `{decrypt, key, round_keys, words, plan, states, result}`，`states` 是每步之后的 9 个状态 |
| `core.encrypt_with_keys(block, keys)` / `decrypt_with_keys` | 已展开轮密钥的快速路径，不做输入检查（供穷举类循环使用） |
| `core.substitute_nibbles / shift_rows / mix_columns` | 单个变换，状态 → 状态 |
| `formats.parse_value(text, width, name)` | `width` 位二进制或 `width/4` 位十六进制 → 整数；不合法抛 `ValueError`（消息含字段名） |
| `formats.describe(value, width=16)` | `{value, bits, grouped, hex}` |
| `gf16.multiply(a, b)` / `gf16.describe_product(a, b)` | GF(2⁴) 乘积 / `{value, text}`（含多项式推导文字） |
| `implementations.get_implementation(key)` | `Implementation(key, name, style, encrypt, decrypt)`，key 为 `"A"`、`"B"`、`"C"` |
| `modes.text_to_bytes / bytes_to_text / printable_view` | 文本 ↔ 字节（UTF-8）/ 乱码视图（不可打印字节显示 `·`） |
| `modes.pad(data, scheme)` / `unpad` | `scheme` 为 `zero`、`pkcs7`、`none` |
| `modes.ecb_encrypt(data, key, padding="zero", cipher=A)` → `list[int]` / `ecb_decrypt(blocks, key, padding, cipher)` → `bytes` | 第 3 关；`cipher` 可换成任意实现 |
| `modes.random_iv()` | 随机 16 位 IV（`secrets`） |
| `modes.cbc_encrypt_blocks(blocks, key, iv, cipher)` / `cbc_decrypt_blocks` | 分组列表 ↔ 分组列表；`cbc_encrypt_bytes` / `cbc_decrypt_bytes` 额外处理填充 |
| `multiple.double_encrypt(block, key32, cipher)` / `double_decrypt` | 32 位密钥 `K1‖K2` |
| `multiple.triple_encrypt(block, key, mode, cipher)` / `triple_decrypt` | `mode` 为 `ede2`（32 位）或 `ede3`（48 位） |
| `multiple.meet_in_the_middle(pairs)` | `[(P, C), …]`（1–16 对）→ `{candidates, counts, block_operations, table_entries, table_ms, elapsed_ms}` |
| `experiments.mitm_experiment(pairs, secret_key=None)` | 在攻击结果上增加候选表、穷举估算、加速比、`secret_found` / `unique` |
| `experiments.cbc_tamper_experiment(plaintext, key, iv, action, padding, cipher)` | `action = {type, index, other?, bit?, value?}`，`type` 为 `replace` / `flip` / `set` / `swap`，下标从 0 开始；返回逐块状态（`intact` / `bitflip` / `garbled`） |
| `exchange.make_exchange(key, plaintexts, cipher)` / `verify_exchange(document, cipher)` / `verify_vectors` / `parse_vector_lines` | 交换文件 |
| `visualization.visual_trace(block, key, operation)` | 图解数据，见下 |
| `visualization.simulate_group(key, plaintexts)` / `simulate_peers(key, plaintexts, group_a, group_b)` | 组内 3×3 互验 / 组间 A↔B 互测，结果带 `simulation: true` 和说明 |
| `selftest.run_level(level)` / `run_all()` | 五关自检，每项含 `name / passed / detail / ms` |

参数错误统一抛 `ValueError`；命令行打印简短错误并返回退出码 2，`verify` / `selftest` 有不一致返回 1。

## HTTP 接口

所有 POST 使用 JSON，成功返回 200，输入错误返回 400 和 `{"error": "说明"}`。服务限定回环地址的 Host，拒绝非本机同源的 Origin（403），请求体上限 256 KiB（拒绝前会先读掉请求体，避免连接被重置而丢失错误响应），不记录请求参数。静态文件只服务 `STATIC_FILES` 中显式列出的路径，其余一律 404。响应头带严格的 CSP（`script-src 'self'; style-src 'self'`，不允许内联脚本和样式）、`nosniff`、`no-store`。这是本机课程 GUI 的接口，不是经过生产安全加固的互联网服务。

| 路由 | 请求字段 | 返回要点 |
| --- | --- | --- |
| `GET /api/spec` | — | S 盒、逆 S 盒、乘法表、列混淆矩阵、轮常数、模多项式、实现说明 |
| `/api/visual` | `operation`、`block`、`key` | 图解数据（下节） |
| `/api/block` | `operation`、`block`、`key`、`implementation` | 结果与轮密钥（`describe` 格式） |
| `/api/group` | `key`；`plaintexts`（每行一个）或 `random`（个数） | 组内互验：`counts`、`rows`（最多 256 行）、`passed` |
| `/api/simulate` | `key`、`plaintexts`、`group_a`、`group_b` | 组间互测：`counts`、`rows`、`group_a/b`、`demo` |
| `/api/export` | `key`、`plaintexts`、`implementation` | 交换文件（JSON 对象） |
| `/api/verify` | `document`（JSON 对象）或 `lines`（三列文本）、`implementation` | `passed`、`total`、`encrypt_passed`、`decrypt_passed`、`results` |
| `/api/ascii` | `operation`、`key`、`padding`；加密用 `text`，解密用 `cipher` + `cipher_format`（`hex` / `base64`） | 分组明细、`cipher_hex`、`cipher_base64`、`cipher_view`；解密返回 `text`、`padding_ok` |
| `/api/double` | `operation`、`key`（32 位）、`block` | 每一重的输入、密钥、输出 |
| `/api/triple` | `operation`、`mode`、`key`、`block` | 三步计算链与子密钥 |
| `/api/mitm/example` | `pairs`（1–16） | 随机 32 位密钥与明密文对 |
| `/api/mitm` | `pairs`（每行 `明文 密文`）、`secret`（可选，仅用于结束后核对） | `counts`、候选（前 32 个）、`block_operations`、耗时、穷举估算、`speedup`、`secret_found`、`unique` |
| `/api/cbc` | `operation`、`key`、`iv`（加密时留空则随机）、`padding`；加密用 `text`，解密用 `cipher`（十六进制） | 加密：`rows`、`package_hex`（IV ‖ 密文）、ECB / CBC 重复分组数；解密：`text`、`padding_ok` |
| `/api/cbc/tamper` | `key`、`iv`、`padding`、`text`、`action` | 逐块状态、预测差分、原文 / 篡改后文本、汇总 |
| `/api/selftest` | `level`（1–5 或 `"all"`） | 各检查项的结果与用时 |

## 图解数据（`visual_trace`）

返回 `{mode, spec_id, input, key, result, words, round_keys, states, outline, steps, roundtrip}`：

- `states`：本次运算每一步之后的 9 个 16 位状态；`roundtrip` 是反方向再算一遍的 `{operation, input, result, states, matches}`，整体结构图的另一侧据此绘制。
- `outline`：`{encrypt: […], decrypt: […]}`，每项 `{index, kind, group, round, label, name, key_name, description}`，描述两种方向的 8 个变换及其所属的轮（`pre / round1 / round2 / post`，与教材图 D.1 的方框分组一致）。
- `steps`：按计算顺序的 13 步，`phase` 依次为 `structure`（1 步）、`key`（4 步）、`cipher`（8 步）。

| `kind` | 主要字段 | 前端渲染约定 |
| --- | --- | --- |
| `structure` | `block`、`key`、`block_name` | 图 D.2：位串 → 半字节 → 状态矩阵；密钥字 |
| `key_expansion` | `target`（2–5）、`known`、`left`、`right`、`g`、`result` | 图 D.5；`g = {input, rotated, substituted, round_index, round_constant, output, lookups}`，w₃、w₅ 步骤没有 `g` |
| `add_key` | `key`、`key_name`、`xor[{position, state, key, result}]` | 状态 ⊕ 轮密钥，逐半字节 |
| `substitute` / `inv_substitute` | `table`、`lookups[{position, input, row, column, output}]` | 高亮 S 盒中的行列交点 |
| `shift_rows` / `inv_shift_rows` | `mapping = [0, 3, 2, 1]` | 输出位置 i 取输入位置 `mapping[i]` |
| `mix_columns` / `inv_mix_columns` | `matrix`、`terms[{position, parts[{coefficient, source, value, product, text}], result}]` | 矩阵乘法与每个 GF(2⁴) 乘法的多项式推导 |

位置编号 0–3 对应 N0..N3，即 `S₀,₀ S₁,₀ S₀,₁ S₁,₁`。所有数值都是整数，由前端格式化为十六进制 / 二进制。

## 前端约定

- 用户输入只通过 `textContent` 进入页面，不拼接 HTML；响应头的 CSP 不允许内联样式，所以动态样式用 CSS 类或 SVG 属性。
- 播放器（`SAESVisuals.createPlayer`）是通用的：每个场景提供 `render(step, index) → {node, frame(progress, animated)}`。第 1 关用 `createCipherPlayer`，组间传输动画用 `transferScene`。播放状态与计算状态分开：选择某一步时直接显示该步的结果，点“播放”才按进度动画；系统启用“减少动态效果”时不播放。
- 每个关卡第一次显示时才运行默认示例（第 4 关含约 3 秒的攻击），所以打开页面是快的。
- 图表遵循单系列单色、对数坐标写明、数值标在柱端、附表格视图；状态用图标 + 文字 + 色条，不只靠颜色。

## 测试

```bash
python -m unittest discover -v          # 全部（约 1 分钟，含全空间对照）
SAES_FAST=1 python -m unittest discover # 跳过两个最耗时的全空间对照
node scripts/check_ui.mjs               # 浏览器端到端检查（需要 Chrome / Edge 与 Node 22+）
python scripts/generate_report.py       # 真实实验并重新生成 docs/test-report.md
```

| 测试文件 | 覆盖 |
| --- | --- |
| `tests/test_core.py` | GF(2⁴) 乘法表逐格对照教材表 D.2、S 盒 / 逆 S 盒版面、S 盒等于“求逆 + 仿射变换”的构造、教材 D.2.1–D.2.4 与 D.3 示例、教材示例是同一次加密（A749 / 2D55）、附件 D.2 的位运算公式对全部 65536 个状态、D.5 的 IMC 分配律、已知向量 6F6B / A73B 的每一步、固定密钥下加密是排列、非法输入；三种实现 3000 组随机对照，以及 65536 个明文（两把密钥）与 65536 把密钥的全空间对照 |
| `tests/test_levels.py` | 交换文件（导出 / 核验 / 篡改检出 / 约定不同被拒绝 / 三列文本）、组内 / 组间模拟、字符串分组与填充、双重 / 三重定义与密钥顺序、中间相遇攻击的完整性与完备性（候选集合与另行计算的结果逐项相等）、CBC 定义与 IV、四种篡改方式的状态与预测差分 |
| `tests/test_visualization.py` | 13 步的顺序与分组、状态衔接、密钥扩展各步、每个变换的细节数据用教材定义独立重算、反方向回验与流程纲要 |
| `tests/test_server.py` | 全部静态文件与安全响应头、路径穿越、主机 / 来源限制、畸形请求（含重复 40 次的“拒绝响应必达”回归测试）、每个路由的正常与错误输入 |
| `tests/test_cli.py` | 命令行输出与退出码 |

`tests/textbook.py` 按原书抄录了表 D.1 / D.2 和示例，**生产代码不引用它**，所以测试能独立核对 `saes` 里的常量；三种实现是同一作者写的，它们互相印证实现正确，但不代表另一组的实测。

## 代码规范

- 命名：Python snake_case、JavaScript camelCase，名字描述用途；避免单字符变量（仅临时循环下标）。
- 注释：只写算法含义、教材对应关系和不明显的约定；模块和公开函数带说明文档字符串。
- 函数式：变换是纯函数，流程用数据描述并用 `reduce` / `accumulate` 组合，重复逻辑抽成函数。

## 扩展与修改

修改任何参数（S 盒、矩阵、RCON、半字节排列）都要同步：`SPEC_ID`、实现 B 与 C、`tests/textbook.py`、图解数据与前端、测试和文档，并重新运行全部检查。不要为了让测试通过而修改期望值。
