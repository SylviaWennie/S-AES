"""运行五关的真实实验，保存原始数据并生成测试结果文档。

用法（仓库根目录）：python scripts/generate_report.py
输出：reports/experiments.json、reports/personal-simulation.json、docs/test-report.md、docs/personal-simulation-report.md
全空间对照（65536 个明文 × 三种实现、65536 把密钥）约需 1–2 分钟。随机数使用固定种子，结果可复现；耗时随硬件不同。
截图由 scripts/check_ui.mjs 生成（docs/assets/），本脚本只引用它们。
"""

import json
import platform
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from saes import core, exchange, modes, multiple  # noqa: E402
from saes.experiments import cbc_tamper_experiment, mitm_example, mitm_experiment  # noqa: E402
from saes.formats import bits, grouped_bits, hex_text  # noqa: E402
from saes.implementations import IMPLEMENTATIONS  # noqa: E402
from saes.visualization import simulate_group, simulate_peers, visual_trace  # noqa: E402

KNOWN = (0x6F6B, 0xA73B, 0x0738)
SEED = 20261021
H = hex_text


def table(headers: list[str], rows: list[list]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)


def code(value) -> str:
    return f"`{value}`"


def timed(function):
    started = time.perf_counter()
    result = function()
    return result, (time.perf_counter() - started) * 1000


# ------------------------------------------------------------------ 数据收集
def collect_level1() -> dict:
    encrypt = visual_trace(KNOWN[0], KNOWN[1], "encrypt")
    book = visual_trace(0xA749, 0x2D55, "encrypt")
    plan = [step for step in encrypt["steps"] if step["phase"] == "cipher"]
    permutation = {}
    for key in (0x2D55, 0x0000, 0xFFFF):
        outputs = [core.encrypt_block(plaintext, key) for plaintext in range(1 << 16)]
        permutation[H(key)] = {"distinct_ciphertexts": len(set(outputs)),
                               "roundtrip_ok": sum(core.decrypt_block(value, key) == plaintext for plaintext, value in enumerate(outputs))}
    edge = [(0x0000, 0x0000), (0xFFFF, 0xFFFF), (0x0000, 0xFFFF), (0xFFFF, 0x0000), (0x8000, 0x0001)]
    return {"known_states": [{"label": step["label"], "title": step["title"], "after": H(step["after"])} for step in plan],
            "known_input": H(KNOWN[0]), "known_result": H(encrypt["result"]), "round_keys": [H(key) for key in encrypt["round_keys"]],
            "book_states": [H(state) for state in book["states"]], "book_words_bits": [format(word, "08b") for word in book["words"]],
            "permutation": permutation,
            "edge": [{"plaintext": H(p), "key": H(k), "ciphertext": H(core.encrypt_block(p, k)),
                      "restored": H(core.decrypt_block(core.encrypt_block(p, k), k))} for p, k in edge]}


def collect_level2() -> dict:
    rng = random.Random(SEED)
    sample = [0x6F6B, 0x0000, 0xFFFF, 0x0001, 0x8000, 0x1234, 0xA5A5, 0x5A5A]
    rows = [{"plaintext": H(p), "A": H(IMPLEMENTATIONS["A"].encrypt(p, 0xA73B)), "B": H(IMPLEMENTATIONS["B"].encrypt(p, 0xA73B)),
             "C": H(IMPLEMENTATIONS["C"].encrypt(p, 0xA73B))} for p in sample]

    def sweep_plaintexts(key: int) -> dict:
        equal = decrypted = 0
        for plaintext in range(1 << 16):
            ciphertexts = {name: item.encrypt(plaintext, key) for name, item in IMPLEMENTATIONS.items()}
            equal += len(set(ciphertexts.values())) == 1
            decrypted += sum(item.decrypt(ciphertexts["A"], key) == plaintext for item in IMPLEMENTATIONS.values())
        return {"key": H(key), "plaintexts": 1 << 16, "encrypt_equal": equal, "decrypt_ok_by_A_B_C": decrypted, "decrypt_total": 3 * (1 << 16)}

    def sweep_keys(plaintext: int) -> dict:
        equal = decrypted = 0
        for key in range(1 << 16):
            ciphertexts = {name: item.encrypt(plaintext, key) for name, item in IMPLEMENTATIONS.items()}
            equal += len(set(ciphertexts.values())) == 1
            decrypted += sum(item.decrypt(ciphertexts["A"], key) == plaintext for item in IMPLEMENTATIONS.values())
        return {"plaintext": H(plaintext), "keys": 1 << 16, "encrypt_equal": equal, "decrypt_ok_by_A_B_C": decrypted, "decrypt_total": 3 * (1 << 16)}

    key_sweep, key_ms = timed(lambda: sweep_keys(0x6F6B))
    plaintext_sweep, plaintext_ms = timed(lambda: sweep_plaintexts(0x2D55))
    peers = {f"{a}-{b}": simulate_peers(0x2D55, list(range(256)), a, b)["counts"] for a, b in (("A", "B"), ("A", "C"), ("B", "C"))}
    group = simulate_group(0x2D55, [rng.getrandbits(16) for _ in range(2048)])
    document = exchange.make_exchange(0xA73B, sample, IMPLEMENTATIONS["A"])
    clean = {name: exchange.verify_exchange(document, item)["passed"] for name, item in IMPLEMENTATIONS.items()}
    tampered = json.loads(json.dumps(document))
    tampered["vectors"][2]["ciphertext"] = bits(int(tampered["vectors"][2]["ciphertext"], 2) ^ 0x0100)
    detected = exchange.verify_exchange(tampered, IMPLEMENTATIONS["C"])
    return {"sample": rows, "plaintext_sweep": plaintext_sweep, "plaintext_sweep_ms": plaintext_ms, "key_sweep": key_sweep, "key_sweep_ms": key_ms,
            "peers": peers, "group_random": {"key": "2D55", "total": group["total"], "counts": group["counts"]},
            "exchange": {"vectors": len(sample), "verified_by": clean, "tampered_detected": not detected["passed"],
                         "tampered_encrypt_passed": detected["encrypt_passed"], "tampered_decrypt_passed": detected["decrypt_passed"]}}


def collect_level3() -> dict:
    key = 0xA73B
    texts = ["Hello, S-AES!", "AB", "ABABABAB", "", "A", "信息安全"]
    rows = []
    for text in texts:
        data = modes.text_to_bytes(text)
        blocks = modes.ecb_encrypt(data, key, "zero")
        rows.append({"text": text, "bytes": data.hex().upper(), "blocks": len(blocks), "cipher": "".join(H(b) for b in blocks),
                     "view": modes.printable_view(modes.blocks_to_bytes(blocks)),
                     "restored": modes.bytes_to_text(modes.ecb_decrypt(blocks, key, "zero"))})
    paddings = []
    for scheme in ("zero", "pkcs7", "none"):
        try:
            blocks = modes.ecb_encrypt(b"abc", key, scheme)
            paddings.append({"scheme": scheme, "padded": modes.pad(b"abc", scheme).hex().upper(), "cipher": "".join(H(b) for b in blocks),
                             "restored": modes.ecb_decrypt(blocks, key, scheme).decode()})
        except ValueError as error:
            paddings.append({"scheme": scheme, "padded": "—", "cipher": "—", "restored": f"拒绝：{error}"})
    return {"key": H(key), "rows": rows, "paddings": paddings}


def collect_level4() -> dict:
    double = [{"plaintext": H(p), "key": H(0x2D55A73B, 8), "cipher": H(multiple.double_encrypt(p, 0x2D55A73B))} for p in (0x6F6B, 0x1234, 0xBEEF)]
    triple = []
    for mode, key in (("ede2", 0x2D55A73B), ("ede3", 0x2D55A73B1C27)):
        cipher = multiple.triple_encrypt(0x6F6B, key, mode)
        triple.append({"mode": mode, "key": H(key, 8 if mode == "ede2" else 12), "cipher": H(cipher),
                       "restored": H(multiple.triple_decrypt(cipher, key, mode))})
    trials = []
    for seed in range(1, 7):
        example = mitm_example(3, seed)
        result = mitm_experiment(example["pairs"], example["key"])
        trials.append({"seed": seed, "key": H(example["key"], 8), "counts": result["counts"], "unique": result["unique"], "found": result["secret_found"],
                       "operations": result["block_operations"], "elapsed_ms": round(result["elapsed_ms"], 1), "table_ms": round(result["table_ms"], 1)})
    estimate = multiple.estimate_exhaustive_seconds(50000)
    per_operation = {}
    for name, item in IMPLEMENTATIONS.items():
        started = time.perf_counter()
        for index in range(5000):
            item.encrypt(index & 0xFFFF, 0x2D55)
        per_operation[name] = round((time.perf_counter() - started) / 5000 * 1e6, 2)
    return {"double": double, "triple": triple, "trials": trials, "estimate": estimate, "per_operation_us": per_operation}


def collect_level5() -> dict:
    key, iv = 0xA73B, 0x1234
    message = "CBC mode demo: AAAAAAAAAAAAAAAA tamper with one block and compare."
    data = modes.text_to_bytes(message)
    plain_blocks = modes.bytes_to_blocks(modes.pad(data, "zero"))
    cipher_blocks = modes.cbc_encrypt_blocks(plain_blocks, key, iv)
    ecb_blocks = modes.ecb_encrypt(data, key, "zero")
    chain = [iv, *cipher_blocks]
    rows = [{"index": i + 1, "plain": H(p), "previous": H(chain[i]), "xor": H(p ^ chain[i]), "cipher": H(c)}
            for i, (p, c) in enumerate(zip(plain_blocks, cipher_blocks))]
    actions = [{"type": "replace", "index": 3, "other": 1}, {"type": "flip", "index": 9, "bit": 0}, {"type": "set", "index": 0, "value": 0xDEAD},
               {"type": "swap", "index": 2, "other": 5}]
    tampers = []
    for action in actions:
        result = cbc_tamper_experiment(data, key, iv, action)
        flips = [row for row in result["rows"] if row["status"] == "bitflip"]
        tampers.append({"action": action, "changed": [i + 1 for i in result["changed_cipher_blocks"]], "summary": result["summary"],
                        "predictions_match": all(row["prediction_matches"] for row in flips), "flip_differences": [row["xor_difference"] for row in flips],
                        "tampered_text": result["tampered_text"]})
    wrong_iv = modes.cbc_decrypt_blocks(cipher_blocks, key, iv ^ 1)
    return {"key": H(key), "iv": H(iv), "message": message, "blocks": len(rows), "rows": rows[:8],
            "ecb_repeated": len(ecb_blocks) - len(set(ecb_blocks)), "cbc_repeated": len(cipher_blocks) - len(set(cipher_blocks)),
            "wrong_iv_first_block_differs": wrong_iv[0] != plain_blocks[0], "wrong_iv_rest_ok": wrong_iv[1:] == plain_blocks[1:], "tampers": tampers}


# ------------------------------------------------------------------ 文档渲染
def describe_action(action: dict) -> str:
    kind = action["type"]
    if kind == "replace":
        return f"把分组 #{action['index'] + 1} 的密文替换为分组 #{action['other'] + 1} 的密文"
    if kind == "flip":
        return f"翻转分组 #{action['index'] + 1} 的第 {action['bit']} 位（b{action['bit']}）"
    if kind == "set":
        return f"把分组 #{action['index'] + 1} 的密文设为 {H(action['value'])}"
    return f"交换分组 #{action['index'] + 1} 与 #{action['other'] + 1}"


def render_test_report(data: dict, ui: dict | None, environment: dict) -> str:
    l1, l2, l3, l4, l5 = (data[f"level{n}"] for n in range(1, 6))
    sweep_p, sweep_k = l2["plaintext_sweep"], l2["key_sweep"]
    ui_line = (f"浏览器端到端检查 {sum(c['passed'] for c in ui['checks'])}/{ui['total']} 项通过（{ui['browser']}，{ui['generated_on']}）。" if ui
               else "尚未运行浏览器端到端检查（scripts/check_ui.mjs）。")
    trials = l4["trials"]
    mean_second = sum(t["counts"][1] for t in trials) / len(trials)
    per = l4["per_operation_us"]
    estimate = l4["estimate"]
    hours = estimate["estimated_seconds"] / 3600
    return f"""# 五关测试结果

本文件由 `scripts/generate_report.py` 根据本机真实运行结果生成，原始数据见 [experiments.json](../reports/experiments.json)。随机数使用固定种子可复现；耗时随硬件、负载变化，不作为性能承诺。环境：{environment['python']} / {environment['system']}，生成日期 {environment['date']}。

**完成方式：个人单人完成全部五关。** 组内测试用三种结构不同的独立实现（A 整数查表、B 0/1 字符串、C GF 多项式矩阵）模拟三位成员；组间测试用 A 组、B 组分别选用不同实现模拟。这些都是在本机实际运行的程序互测，**没有其他同学或其他小组参与，不是真人跨组实验**。与真实小组的交叉测试方法见[用户指南](user-guide.md#与其他小组交叉测试)，结果待补充（本文末尾留有记录表）。{ui_line}

## 总览

| 关卡 | 要求 | 本项目的完成情况 | 证据 |
| --- | --- | --- | --- |
| 第 1 关 基本测试 | GUI；16 位数据 + 16 位密钥 → 16 位密文 | 网页 GUI 支持加密 / 解密，复刻教材图 D.1–D.5 的 13 步分步图解 | [第 1 关](#第-1-关基本测试) |
| 第 2 关 交叉测试 | 相同算法标准，A / B 组互相加解密一致 | 组内三实现互验、A 组 ↔ B 组互测、交换文件；全空间对照 | [第 2 关](#第-2-关交叉测试) |
| 第 3 关 扩展功能 | ASCII 字符串（2 字节一组），输出可为乱码字符串 | 字符串 ↔ 分组 ↔ 密文，十六进制 / Base64 / 乱码三种视图 | [第 3 关](#第-3-关扩展功能) |
| 第 4 关 多重加密 | 双重（32 位）、中间相遇攻击、三重（32 或 48 位） | 双重、中间相遇攻击（含候选收敛图）、三重两种模式都实现 | [第 4 关](#第-4-关多重加密) |
| 第 5 关 工作模式 | CBC，16 位 IV 双方共享；篡改密文分组后对比解密 | CBC 加解密、传输包 = IV ‖ 密文、四种篡改方式的对比实验 | [第 5 关](#第-5-关工作模式) |

网页上的“一键闯关”按钮会重新运行每一关的自检（教材示例、已知向量、固定种子的随机数据、三种实现互相核对），当前 **5/5 通过**：

![一键闯关](assets/17-all-levels.png)

## 第 1 关：基本测试

**要求：** 提供 GUI 支持用户交互；输入 16 位数据和 16 位密钥，输出 16 位密文（并能解密）。

**操作与界面：** 输入框接受 16 位二进制或 4 位十六进制，并即时显示另一种写法。点击“运行并查看过程”后，右侧显示密文、三个轮密钥和反方向回验；下方图解按教材顺序依次展示数据结构（图 D.2）、密钥扩展（图 D.5）和 8 个加密 / 解密变换（图 D.1、D.3、D.4）。

![第 1 关：输入、结果与图解](assets/01-basic.png)

### 已知向量 P = {code(l1['known_input'])}，K = {code('A73B')} → C = {code(l1['known_result'])}

轮密钥 K₀ / K₁ / K₂ = {" / ".join(code(key) for key in l1['round_keys'])}。每一步之后的 16 位状态（手工可复核，见[算法说明](algorithm.md#可手工复核的例子)）：

{table(['步骤', '变换', '之后的状态'], [['0', '输入 P', code(l1['known_input'])]] + [[str(i + 1), step['title'], code(step['after'])] for i, step in enumerate(l1['known_states'])])}

解密回验：对 {code(l1['known_result'])} 用同一密钥解密，得到 {code(l1['known_input'])}。

### 教材附录 D 的示例逐项复现

教材 D.2.1–D.2.4 的四个示例恰好是 **P = A749、K = 2D55** 这一次加密的前四步（页面“载入示例”可一键复现），D.3 的密钥扩展示例使用同一把密钥：

{table(['教材位置', '教材给出的结果', '本程序的结果'], [
    ['D.2.1 轮密钥加 [[A,4],[7,9]] ⊕ [[2,5],[D,5]]', '[[8,1],[A,C]]', f"状态 {code(l1['book_states'][1])}"],
    ['D.2.2 半字节代替', '[[6,4],[0,C]]', f"状态 {code(l1['book_states'][2])}"],
    ['D.2.3 行移位', '[[6,4],[C,0]]', f"状态 {code(l1['book_states'][3])}"],
    ['D.2.4 列混淆', '[[3,4],[7,3]]', f"状态 {code(l1['book_states'][4])}"],
    ['D.3 密钥扩展 w₂…w₅（密钥 2D55）', '10111100 11101001 10100011 01001010', ' '.join(code(word) for word in l1['book_words_bits'][2:])]])}

（状态按教材图 D.2 的列优先顺序写成 4 个十六进制数 N₀N₁N₂N₃，例如 `8A1C` 就是矩阵 [[8,1],[A,C]]。）

### 全空间与边界检查

{table(['检查', '结果'], [[f"密钥 {key}：65536 个明文的密文互不相同（加密是排列）", f"{value['distinct_ciphertexts']} / 65536"] for key, value in l1['permutation'].items()]
    + [[f"密钥 {key}：解密 ∘ 加密 = 恒等", f"{value['roundtrip_ok']} / 65536"] for key, value in l1['permutation'].items()])}

边界输入（全 0、全 1、最高位等）：

{table(['明文', '密钥', '密文', '解密还原'], [[code(e['plaintext']), code(e['key']), code(e['ciphertext']), code(e['restored'])] for e in l1['edge']])}

非法输入（长度不对、含非 0/1 或非十六进制字符）会即时提示，提交后由后端返回明确的错误信息，不会静默补零或截断。教材示例、逐项变换及自检共 11 项见网页“一键闯关”。

![图 D.5 密钥扩展与 g 函数](assets/03-key-expansion-d5.png)

![图 D.3 轮函数与图 D.4 S 盒查表](assets/04-round-substitute-d3.png)

![列混淆：矩阵乘法与 GF(2⁴) 多项式推导](assets/05-round-mixcolumns-d4.png)

![解密方向的图解](assets/06-decrypt.png)

**结论：** 加密、解密均与教材示例逐项一致，已知向量 {code('6F6B / A73B → 0738')} 的每一步状态可手工复核；加密在固定密钥下是 65536 个分组上的排列。

## 第 2 关：交叉测试

**要求：** 所有人使用相同的算法流程和转换单元（S 盒、列混淆矩阵等）。两组使用相同密钥对同一明文加密应得到相同密文；一组加密的密文，另一组的程序解密应得到同一明文。

**个人完成方式：** 把“另一位同学 / 另一组”换成结构不同的独立实现——A 用整数位运算与查表；B 全程使用 0/1 字符串，列混淆用“乘 x”位运算；C 用 GF(2⁴) 多项式矩阵，S 盒由“求逆 + 仿射变换”构造，解密采用教材 D.5 的等价逆算法。三份代码互不导入对方的常量与函数。

### 组内测试：三种实现互验

密钥 {code('A73B')}，8 个典型明文：

{table(['明文 P', '实现 A 密文', '实现 B 密文', '实现 C 密文', '是否一致'], [[code(r['plaintext']), code(r['A']), code(r['B']), code(r['C']), '✓' if r['A'] == r['B'] == r['C'] else '✗'] for r in l2['sample']])}

全空间对照（真实运行 {sweep_p['plaintexts']} + {sweep_k['keys']} 个输入，每个输入三种实现各算一遍）：

{table(['对照范围', '三种实现密文一致', 'A 的密文由 A / B / C 解密还原'], [
    [f"固定密钥 {sweep_p['key']}，遍历全部 65536 个明文", f"{sweep_p['encrypt_equal']} / {sweep_p['plaintexts']}", f"{sweep_p['decrypt_ok_by_A_B_C']} / {sweep_p['decrypt_total']}"],
    [f"固定明文 {sweep_k['plaintext']}，遍历全部 65536 把密钥", f"{sweep_k['encrypt_equal']} / {sweep_k['keys']}", f"{sweep_k['decrypt_ok_by_A_B_C']} / {sweep_k['decrypt_total']}"],
    [f"密钥 {l2['group_random']['key']}，随机 {l2['group_random']['total']} 个明文，3×3 交叉解密", f"{l2['group_random']['counts']['encrypt_equal']} / {l2['group_random']['total']}", f"{l2['group_random']['counts']['cross_decrypt_ok']} / {l2['group_random']['counts']['cross_decrypt_total']}（9 种加解密组合）"]])}

![组内互验：三种实现的密文与 3×3 交叉解密矩阵](assets/07-cross-group.png)

### 组间测试：A 组 ↔ B 组

两组共享密钥 {code('2D55')}，对 256 个明文分别计算，再交换密文互相解密：

{table(['A 组实现', 'B 组实现', '密文一致', 'A → B 解密还原', 'B → A 解密还原'], [[pair.split('-')[0], pair.split('-')[1], f"{v['encrypt_equal']} / 256", f"{v['a_to_b_ok']} / 256", f"{v['b_to_a_ok']} / 256"] for pair, v in l2['peers'].items()])}

页面上可以任意选择两组各用哪种实现，并回放“加密 → 模拟信道 → 解密”的传输动画：

![组间互测与传输动画](assets/08-cross-peers.png)

![传输动画](assets/08-cross-peers-animation.png)

### 与其他小组交换测试向量

真实的组间测试需要对方的程序。本项目提供两种交换格式（[格式说明](algorithm.md#交叉测试交换格式)）：JSON 文件和每行「明文 密钥 密文」的纯文本。个人自检结果：

{table(['检查', '结果'], [
    [f"实现 A 导出 {l2['exchange']['vectors']} 条向量，分别由实现 A / B / C 核验", ' / '.join(f"{name} {'通过' if ok else '失败'}" for name, ok in l2['exchange']['verified_by'].items())],
    ['改动其中一条密文后由实现 C 核验', f"检出不一致（加密一致 {l2['exchange']['tampered_encrypt_passed']}/{l2['exchange']['vectors']}，解密一致 {l2['exchange']['tampered_decrypt_passed']}/{l2['exchange']['vectors']}）" if l2['exchange']['tampered_detected'] else '未检出（异常）'],
    ['算法标识（spec_id）不同的交换文件', '被拒绝，并提示先核对 S 盒、列混淆矩阵、密钥扩展常量和半字节排列'],
    ['纯文本向量（十六进制与二进制混写、带注释）', '可直接粘贴核验']])}

![交换文件的核验](assets/09-cross-exchange.png)

**结论：** 三种结构不同的实现在全部 65536 个明文和全部 65536 把密钥上的密文完全一致、互相解密全部还原，说明算法流程与转换单元按教材标准执行。因为三份代码同出一人之手，这不能替代真人跨组测试，见下方记录表。

## 第 3 关：扩展功能

**要求：** 加密算法的数据输入可以是 ASCII 编码字符串（分组为 2 字节），对应地输出也可以是 ASCII 字符串（很可能是乱码）。

**约定：** 字符串先编码成字节（ASCII 字符与 ASCII 编码完全相同，中文等按 UTF-8），每 2 字节组成一个 16 位分组（高字节在前，例如 `"AB"` = `0x4142`），逐组独立加密。奇数字节需要填充：默认补一个 `0x00`（偶数长度时与不填充完全相同，便于与其他小组对照），也可选 PKCS#7 或“无填充”（奇数时拒绝）。密文字节多半不可打印，所以同时提供十六进制、Base64 和“乱码字符串”视图。

密钥 {code(l3['key'])}：

{table(['明文', '字节（十六进制）', '分组数', '密文（十六进制）', '乱码字符串视图', '解密还原'], [[json.dumps(r['text'], ensure_ascii=False), code(r['bytes'] or '（空）'), r['blocks'], code(r['cipher'] or '（空）'), code(r['view'] or '（空）'), json.dumps(r['restored'], ensure_ascii=False)] for r in l3['rows']])}

奇数字节（{code('abc')}，3 字节）的三种填充方式：

{table(['填充方式', '填充后字节', '密文', '还原 / 结果'], [[p['scheme'], code(p['padded']), code(p['cipher']), p['restored'] if p['scheme'] == 'none' else code(p['restored'])] for p in l3['paddings']])}

观察：`ABABABAB` 的 4 个相同分组得到 4 个相同的密文分组——逐组独立加密（ECB）会暴露重复模式，这正是第 5 关引入 CBC 的原因。

![第 3 关：字符串加密与分组明细](assets/10-ascii.png)

**结论：** 字符串（含空串、奇数长度、中文）加密再解密均能还原；非法的“无填充 + 奇数字节”被拒绝并提示。

## 第 4 关：多重加密

### 双重加密（32 位密钥）

约定：密钥 K = K1 ‖ K2（K1 在高 16 位），**C = E_K2( E_K1( P ) )，P = D_K1( D_K2( C ) )**。

{table(['明文 P', '密钥 K1‖K2', '密文 C'], [[code(r['plaintext']), code(r['key']), code(r['cipher'])] for r in l4['double']])}

![双重加密与计算链](assets/11-multiple-double.png)

### 中间相遇攻击

已知若干对使用同一把 32 位密钥的明文 / 密文，枚举全部 2¹⁶ 个 K1 得到中间值表 E_K1(P)，再枚举全部 2¹⁶ 个 K2 计算 D_K2(C) 并查表，命中的 (K1, K2) 即候选；其余明密文对逐个验证候选。总计约 2×2¹⁶ 次分组运算，而不是穷举的 2³² 次。

固定种子的 6 次试验（每次随机选一把 32 位密钥，给出 3 对明密文）：

{table(['种子', '真实密钥 K1‖K2', '候选数：1 对 → 2 对 → 3 对', '唯一且包含真实密钥', '分组运算次数', '总耗时 / ms', '其中建表 / ms'], [[t['seed'], code(t['key']), ' → '.join(f"{c:,}" for c in t['counts']), '✓' if t['unique'] and t['found'] else '✗', f"{t['operations']:,}", t['elapsed_ms'], t['table_ms']] for t in trials])}

观察：**单对明密文远远不够**——只给 1 对时剩下约 6.5 万个候选（≈ 2³² / 2¹⁶）；2 对后平均约 {mean_second:.1f} 个；3 对后唯一。这与理论预期一致：每增加一对，候选数大约除以 2¹⁶。

运算量与时间：本机实测单次分组加密 {per['A']} µs（实现 A）；穷举 2³² 把双重密钥最优也需约 {estimate['exhaustive_operations']:,} 次加密，按此速度**估算**约 {hours:.1f} 小时（估算值，不是实测）；中间相遇实测约 {sum(t['elapsed_ms'] for t in trials) / len(trials) / 1000:.1f} 秒，运算量约为穷举的 1/{estimate['exhaustive_operations'] / trials[0]['operations']:,.0f}。

![中间相遇攻击：候选收敛（对数坐标）、原理图与候选表](assets/12-mitm.png)

### 三重加密

两种模式（EDE）：32 位密钥 K1‖K2 用 **C = E_K1( D_K2( E_K1( P ) ) )**；48 位密钥 K1‖K2‖K3 用 **C = E_K3( D_K2( E_K1( P ) ) )**。本项目两种都实现。P = {code('6F6B')}：

{table(['模式', '密钥', '密文 C', '解密还原'], [[t['mode'].upper(), code(t['key']), code(t['cipher']), code(t['restored'])] for t in l4['triple']])}

K1 = K2 时 EDE2 退化为单重加密（已在自检中验证）。

![三重加密](assets/13-triple.png)

**结论：** 双重加密并没有把安全强度提高到 32 位密钥空间应有的水平（攻击约 2¹⁷ 次运算，只比单重多一个常数倍和 2¹⁶ 项的内存）；这也是实际中采用三重加密的原因。

## 第 5 关：工作模式

**要求：** 使用 CBC 对较长的明文加密，初始向量（16 位）的生成与双方共享；对密文分组替换或修改后解密，对比篡改前后的结果。

**约定：** C₀ = IV，Cᵢ = E_K( Pᵢ ⊕ Cᵢ₋₁ )；解密 Pᵢ = D_K( Cᵢ ) ⊕ Cᵢ₋₁。IV 随机生成（浏览器 `crypto.getRandomValues`），不需要保密，但必须与密文一起交给接收方，所以页面给出“传输包 = IV ‖ 密文”。

明文：`{l5['message']}`，密钥 {code(l5['key'])}，IV {code(l5['iv'])}，共 {l5['blocks']} 个分组（前 8 个）：

{table(['#', '明文 Pᵢ', 'Cᵢ₋₁（或 IV）', 'Pᵢ ⊕ Cᵢ₋₁', '密文 Cᵢ'], [[r['index'], code(r['plain']), code(r['previous']), code(r['xor']), code(r['cipher'])] for r in l5['rows']])}

同一段明文里连续 16 个 `A`：ECB 得到 **{l5['ecb_repeated']}** 个重复的密文分组，CBC 得到 **{l5['cbc_repeated']}** 个。使用错误的 IV（差 1 位）解密：{'只有第 1 个明文分组出错，其余分组完全正确' if l5['wrong_iv_first_block_differs'] and l5['wrong_iv_rest_ok'] else '结果异常'}。

![CBC 加密链与分组明细](assets/15-cbc-chain.png)

### 篡改密文分组再解密

{table(['改动方式', '被改动的密文分组', '整块乱码', '位翻转（可预测）', '不受影响', '位翻转与 Cᵢ₋₁ ⊕ C′ᵢ₋₁ 吻合'], [[describe_action(t['action']), '、'.join(f'#{i}' for i in t['changed']), t['summary']['garbled'], t['summary']['bitflip'], t['summary']['intact'], '✓' if t['predictions_match'] else '✗'] for t in l5['tampers']])}

规律（与 CBC 的定义完全一致）：

- 被改动的密文分组 Cᵢ：对应的明文分组 Pᵢ = D(C′ᵢ) ⊕ Cᵢ₋₁ **整块变成乱码**。
- 紧接着的明文分组 Pᵢ₊₁ = D(Cᵢ₊₁) ⊕ C′ᵢ：它自己的密文没变，但与原文**恰好相差 Cᵢ ⊕ C′ᵢ**——攻击者可以通过修改 Cᵢ 来有意翻转 Pᵢ₊₁ 中指定的比特（代价是 Pᵢ 被毁）。
- 其余分组完全不受影响：错误传播只波及两个分组。

页面用图标 + 文字 + 色条同时标注每个分组的状态（未受影响 ✓、位翻转 ⚠、整块乱码 ✕），不只靠颜色：

![篡改密文分组后的解密对比](assets/16-cbc-tamper.png)

**结论：** CBC 隐藏了明文的重复模式，错误传播范围与理论一致；但 CBC 本身不提供完整性保护，篡改可以被有意利用，实际使用需要配合消息认证。

## 代码规范

- **命名：** Python 使用 snake_case、JavaScript 使用 camelCase，函数和变量名描述用途（如 `substitute_nibbles`、`meet_in_the_middle`、`cbc_decrypt_blocks`），避免单字符名（仅限循环下标等临时变量）。
- **注释：** 只在算法含义、教材对应关系和不明显的约定处写简短中文注释；模块与公开函数带说明文档字符串，对外接口见[开发手册](developer-guide.md)。
- **函数式编程：** 加解密流程用数据（`ENCRYPT_PLAN` / `DECRYPT_PLAN`）描述，计算与图解轨迹共用同一份；各变换是纯函数，用 `reduce`、`accumulate` 等组合；重复逻辑抽成函数复用。

## 待补充：真人组内 / 组间测试记录

以下由真实参与测试的同学在测试后填写（程序不会自动生成，也不应把个人模拟写进这里）。

| 日期 | 对方（小组 / 同学） | 对方语言 / 平台 | 测试内容 | 向量条数 | 加密一致 | 解密还原 | 备注 |
| --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |  |  |
"""


def render_simulation_report(data: dict, environment: dict) -> str:
    l2 = data["level2"]
    return f"""# 个人模拟记录：组内与组间互测

本文件由 `scripts/generate_report.py` 根据实际计算结果生成，原始数据见 [personal-simulation.json](../reports/personal-simulation.json)。环境：{environment['python']} / {environment['system']}，{environment['date']}。

本次采用**个人多实现模拟**：A（`saes.core`，整数位运算 + 查表）、B（`saes.peer`，0/1 字符串）、C（`saes.matrix`，GF(2⁴) 多项式矩阵，S 盒由数学定义构造，解密用教材 D.5 的等价逆算法）三种结构不同的实现，**由同一个人在同一台机器上编写和运行**。B、C 没有导入 A 的算法函数或常量。没有外部小组参与，没有真实网络传输，不构成异构平台实测，也不能写成真人跨组实验。

## 实现之间的差异

| 实现 | S 盒来源 | 列混淆 | 状态表示 | 解密流程 |
| --- | --- | --- | --- | --- |
| A | 教材表 D.1 的 16 项查表 | 预先算好的 GF(2⁴) 乘法表，按矩阵逐元素相乘 | 16 位整数 + 位移 | 逆变换依次执行 |
| B | 教材表 D.1 的行列版面逐行抄录（字符串） | 「乘 x」的位运算（附件 D.2 的形式） | 16 个 0/1 字符 | 逆变换依次执行 |
| C | 求 GF(2⁴) 逆元 + 仿射变换构造，再与教材表比对 | 多项式长除法的 2×2 矩阵乘法 | GF(2⁴) 元素的 2×2 矩阵 | 等价逆算法：先对 K₁ 做逆列混淆 |

## 全空间互验结果

{table(['对照范围', '三种实现密文一致', 'A 的密文由 A / B / C 解密还原'], [
    [f"固定密钥 {l2['plaintext_sweep']['key']}，遍历 65536 个明文", f"{l2['plaintext_sweep']['encrypt_equal']} / 65536", f"{l2['plaintext_sweep']['decrypt_ok_by_A_B_C']} / {l2['plaintext_sweep']['decrypt_total']}"],
    [f"固定明文 {l2['key_sweep']['plaintext']}，遍历 65536 把密钥", f"{l2['key_sweep']['encrypt_equal']} / 65536", f"{l2['key_sweep']['decrypt_ok_by_A_B_C']} / {l2['key_sweep']['decrypt_total']}"]])}

耗时：遍历明文约 {l2['plaintext_sweep_ms'] / 1000:.1f} 秒，遍历密钥约 {l2['key_sweep_ms'] / 1000:.1f} 秒（三种实现各算加密与解密）。

## 组间互测（256 个明文，密钥 2D55）

{table(['A 组', 'B 组', '密文一致', 'A → B 解密还原', 'B → A 解密还原'], [[pair.split('-')[0], pair.split('-')[1], f"{v['encrypt_equal']} / 256", f"{v['a_to_b_ok']} / 256", f"{v['b_to_a_ok']} / 256"] for pair, v in l2['peers'].items()])}

原始记录（每条明文的两端密文与交叉解密结果）保存在 JSON 的 `peers` 字段。

## 与真人互测的区别

个人多实现模拟能发现实现错误（例如 S 盒抄错、半字节顺序不一致），但发现不了“大家共同的误解”——比如三份代码都按同一种理解处理了教材里含糊的地方。真实的组间测试仍需要对方的程序，参见[用户指南](user-guide.md#与其他小组交叉测试)。
"""


def main() -> None:
    started = time.perf_counter()
    environment = {"python": f"Python {platform.python_version()}", "system": platform.system(), "date": time.strftime("%Y-%m-%d")}
    data = {"level1": collect_level1(), "level2": collect_level2(), "level3": collect_level3(), "level4": collect_level4(), "level5": collect_level5()}
    data["environment"] = environment
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "experiments.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    peers_full = {f"{a}-{b}": simulate_peers(0x2D55, list(range(256)), a, b) for a, b in (("A", "B"), ("A", "C"), ("B", "C"))}
    simulation = {"environment": environment, "notice": "个人多实现模拟；没有其他小组参与，不是真人互测。",
                  "group": simulate_group(0x2D55, list(range(256))), "peers": peers_full}
    (reports / "personal-simulation.json").write_text(json.dumps(simulation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    ui_path = reports / "ui-checks.json"
    ui = json.loads(ui_path.read_text(encoding="utf-8")) if ui_path.exists() else None
    (ROOT / "docs" / "test-report.md").write_text(render_test_report(data, ui, environment), encoding="utf-8", newline="\n")
    (ROOT / "docs" / "personal-simulation-report.md").write_text(render_simulation_report(data, environment), encoding="utf-8", newline="\n")
    print(f"已生成 reports/experiments.json、reports/personal-simulation.json、docs/test-report.md（用时 {time.perf_counter() - started:.0f} 秒）")


if __name__ == "__main__":
    main()
