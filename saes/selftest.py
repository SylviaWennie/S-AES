"""五关自检：网页「一键闯关」与报告脚本共用。随机数使用固定种子，结果可复现。

自检只做快速的抽样与教材示例核对；全空间穷举对照放在 tests/ 的单元测试里。
"""

import random
from time import perf_counter_ns

from . import core, exchange, gf16, modes, multiple
from .experiments import cbc_tamper_experiment, mitm_example, mitm_experiment
from .formats import bits, hex_text
from .implementations import IMPLEMENTATIONS
from .visualization import simulate_group, simulate_peers, visual_trace

LEVEL_TITLES = {1: "基本测试", 2: "交叉测试", 3: "扩展功能", 4: "多重加密", 5: "工作模式"}
KNOWN_PLAINTEXT, KNOWN_KEY, KNOWN_CIPHERTEXT = 0x6F6B, 0xA73B, 0x0738
SEED = 20261021


def _require(condition: bool, message: str) -> None:
    """显式检查（不用 assert，避免 python -O 时被跳过）。"""
    if not condition:
        raise AssertionError(message)


def _expect(actual, expected, label: str) -> str:
    _require(actual == expected, f"{label}：期望 {expected}，实际 {actual}")
    return f"{label} = {actual}"


def _run(name: str, check) -> dict:
    started = perf_counter_ns()
    try:
        detail, passed = check(), True
    except Exception as error:  # 自检要报告失败原因，而不是中断整个关卡
        detail, passed = f"{type(error).__name__}: {error}", False
    return {"name": name, "passed": passed, "detail": detail, "ms": (perf_counter_ns() - started) / 1e6}


# ---------------------------------------------------------------- 第 1 关
def _textbook_key_expansion() -> str:
    words = " ".join(format(word, "02X") for word in core.expand_key(0x2D55))
    return _expect(words, "2D 55 BC E9 A3 4A", "密钥 2D55 的 w0..w5")


def _textbook_substitution() -> str:
    state = core.join_nibbles(0x8, 0xA, 0x1, 0xC)  # 图中矩阵 [[8,1],[A,C]]
    expected = core.join_nibbles(0x6, 0x0, 0x4, 0xC)  # [[6,4],[0,C]]
    return _expect(hex_text(core.substitute_nibbles(state, core.SBOX)), hex_text(expected),
                   "NS [[8,1],[A,C]] → [[6,4],[0,C]]")


def _textbook_shift_rows() -> str:
    state, expected = core.join_nibbles(0x6, 0x0, 0x4, 0xC), core.join_nibbles(0x6, 0xC, 0x4, 0x0)
    return _expect(hex_text(core.shift_rows(state)), hex_text(expected), "SR [[6,4],[0,C]] → [[6,4],[C,0]]")


def _textbook_mix_columns() -> str:
    state, expected = core.join_nibbles(0x6, 0xC, 0x4, 0x0), core.join_nibbles(0x3, 0x7, 0x4, 0x3)
    forward = core.mix_columns(state, core.MIX_MATRIX)
    _expect(hex_text(forward), hex_text(expected), "MC [[6,4],[C,0]] → [[3,4],[7,3]]")
    _expect(core.mix_columns(forward, core.INV_MIX_MATRIX), state, "IMC(MC(x)) 还原")
    return "MC [[6,4],[C,0]] → [[3,4],[7,3]]，逆列混淆还原"


def _textbook_add_key() -> str:
    return _expect(hex_text(0xA749 ^ 0x2D55), "8A1C", "AK [[A,4],[7,9]] ⊕ [[2,5],[D,5]] → [[8,1],[A,C]]")


def _known_vector() -> str:
    cipher = core.encrypt_block(KNOWN_PLAINTEXT, KNOWN_KEY)
    _expect(hex_text(cipher), hex_text(KNOWN_CIPHERTEXT), "P=6F6B K=A73B 的密文")
    _expect(core.decrypt_block(cipher, KNOWN_KEY), KNOWN_PLAINTEXT, "解密还原")
    return f"P={hex_text(KNOWN_PLAINTEXT)} K={hex_text(KNOWN_KEY)} → C={hex_text(cipher)}，解密还原 P"


def _gf_table() -> str:
    errors = [(a, b) for a in range(16) for b in range(16)
              if gf16.multiply(a, b) != gf16.reduce_modulo(gf16.carryless_product(a, b))]
    _expect(errors, [], "移位相加与多项式长除法两种乘法的不一致项")
    return _expect(gf16.multiply(4, 0xC), 5, "4·C") + "；256 个乘积两种算法一致"


def _inverse_operations() -> str:
    states = range(1 << 16)
    _require(all(core.mix_columns(core.mix_columns(s, core.MIX_MATRIX), core.INV_MIX_MATRIX) == s for s in states),
             "IMC(MC(x)) ≠ x")
    _require(all(core.substitute_nibbles(core.substitute_nibbles(s, core.SBOX), core.INV_SBOX) == s for s in states),
             "INS(NS(x)) ≠ x")
    return "全部 65536 个状态：IMC(MC(x)) = x，INS(NS(x)) = x，ISR 与 SR 相同"


def _random_roundtrip(count: int = 2000):
    def check() -> str:
        rng = random.Random(SEED)
        for _ in range(count):
            plaintext, key = rng.getrandbits(16), rng.getrandbits(16)
            _require(core.decrypt_block(core.encrypt_block(plaintext, key), key) == plaintext,
                     f"P={plaintext:04X} K={key:04X} 未能还原")
        return f"{count} 组随机 (P, K) 加密后解密均还原"
    return check


def _permutation_property() -> str:
    outputs = {core.encrypt_block(plaintext, 0x2D55) for plaintext in range(1 << 16)}
    return _expect(len(outputs), 1 << 16, "固定密钥 2D55 下 65536 个明文对应的不同密文数")


def _visual_trace_consistency() -> str:
    for mode in ("encrypt", "decrypt"):
        trace = visual_trace(KNOWN_PLAINTEXT if mode == "encrypt" else KNOWN_CIPHERTEXT, KNOWN_KEY, mode)
        cipher_steps = [step for step in trace["steps"] if step["phase"] == "cipher"]
        _require(len(trace["steps"]) == 13 and len(cipher_steps) == 8, "步骤数应为 1 + 4 + 8")
        _require(all(a["after"] == b["before"] for a, b in zip(cipher_steps, cipher_steps[1:])), "相邻步骤的状态必须衔接")
        _require(trace["roundtrip"]["matches"], "反方向运算应还原输入")
    return "加密 / 解密图解各 13 步，状态逐步衔接，反向运算还原输入"


# ---------------------------------------------------------------- 第 2 关
def _implementations_known_vector() -> str:
    results = {item.key: hex_text(item.encrypt(KNOWN_PLAINTEXT, KNOWN_KEY)) for item in IMPLEMENTATIONS.values()}
    _expect(set(results.values()), {hex_text(KNOWN_CIPHERTEXT)}, "三种实现对已知向量的密文")
    return "A、B、C 三种实现均得到 " + hex_text(KNOWN_CIPHERTEXT)


def _group_simulation(count: int = 600):
    def check() -> str:
        rng = random.Random(SEED + 2)
        result = simulate_group(rng.getrandbits(16), [rng.getrandbits(16) for _ in range(count)])
        _require(result["passed"], "三种实现出现不一致")
        return (f"{count} 个明文：加密一致 {result['counts']['encrypt_equal']}/{count}，"
                f"3×3 交叉解密 {result['counts']['cross_decrypt_ok']}/{result['counts']['cross_decrypt_total']}")
    return check


def _peer_simulation() -> str:
    result = simulate_peers(0x2D55, list(range(256)), "A", "C")
    _require(result["passed"], "A 组与 B 组出现不一致")
    counts = result["counts"]
    return (f"密钥 2D55，256 个明文：加密一致 {counts['encrypt_equal']}/256，"
            f"A→B {counts['a_to_b_ok']}/256，B→A {counts['b_to_a_ok']}/256")


def _exchange_roundtrip() -> str:
    document = exchange.make_exchange(KNOWN_KEY, [0x0000, 0x6F6B, 0xFFFF, 0x1234])
    _require(exchange.verify_exchange(document, IMPLEMENTATIONS["B"])["passed"], "未篡改的交换文件应当通过")
    document["vectors"][1]["ciphertext"] = bits(KNOWN_CIPHERTEXT ^ 1)
    broken = exchange.verify_exchange(document, IMPLEMENTATIONS["C"])
    _require(not broken["passed"] and broken["encrypt_passed"] == 3, "篡改一条密文应被检出")
    return "交换文件由 A 导出、B 核验通过；改动一条密文后由 C 核验，恰好检出 1 条不一致"


def _exchange_convention_mismatch() -> str:
    document = exchange.make_exchange(KNOWN_KEY, [0x6F6B])
    document["spec_id"] = "other-saes-v9"
    try:
        exchange.verify_exchange(document)
    except ValueError as error:
        return f"算法约定不同的交换文件被拒绝：{error}"
    raise AssertionError("算法约定不同的交换文件不应被接受")


def _text_vector_lines() -> str:
    lines = (f"{hex_text(KNOWN_PLAINTEXT)} {hex_text(KNOWN_KEY)} {hex_text(KNOWN_CIPHERTEXT)}\n"
             f"{bits(0)} {bits(0)} {bits(core.encrypt_block(0, 0))}  # 二进制写法")
    result = exchange.verify_vectors(exchange.parse_vector_lines(lines))
    _require(result["passed"] and result["total"] == 2, "纯文本向量应全部通过")
    return "纯文本向量（十六进制 / 二进制混写，含注释）2 条核验通过"


# ---------------------------------------------------------------- 第 3 关
TEXT_SAMPLES = ("Hello, S-AES!", "AB", "A", "", "S-AES 2026\nline2\ttab", "信息安全导论")


def _text_roundtrip() -> str:
    for text in TEXT_SAMPLES:
        for padding in ("zero", "pkcs7"):
            blocks = modes.ecb_encrypt(modes.text_to_bytes(text), KNOWN_KEY, padding)
            _require(modes.bytes_to_text(modes.ecb_decrypt(blocks, KNOWN_KEY, padding)) == text, f"{text!r}/{padding}")
    return f"{len(TEXT_SAMPLES)} 段文本（空串、单字符、换行、中文）× 2 种填充：加密再解密均还原"


def _text_known_blocks() -> str:
    blocks = modes.ecb_encrypt(b"Hi", KNOWN_KEY)
    expected = core.encrypt_block(0x4869, KNOWN_KEY)  # 'H'=0x48, 'i'=0x69，高字节在前
    _expect(blocks, [expected], "\"Hi\" 的密文分组")
    return f"\"Hi\" = 0x4869 → 密文 {hex_text(expected)}；2 字节一个分组，高字节在前"


def _text_cross_implementation() -> str:
    text = modes.text_to_bytes("Cross-check ASCII text")
    blocks = modes.ecb_encrypt(text, KNOWN_KEY, "zero", IMPLEMENTATIONS["A"])
    _require(modes.ecb_decrypt(blocks, KNOWN_KEY, "zero", IMPLEMENTATIONS["B"]) == text, "B 应能解密 A 的密文")
    _require(modes.ecb_encrypt(text, KNOWN_KEY, "zero", IMPLEMENTATIONS["C"]) == blocks, "C 与 A 的密文应相同")
    return "A 加密的字符串可由 B 解密，C 加密得到相同密文分组"


def _text_edge_cases() -> str:
    try:
        modes.ecb_encrypt(b"abc", KNOWN_KEY, "none")
    except ValueError:
        pass
    else:
        raise AssertionError("无填充 + 奇数字节应被拒绝")
    blocks = modes.ecb_encrypt(b"secret", KNOWN_KEY)
    _require(modes.ecb_decrypt(blocks, KNOWN_KEY ^ 1) != b"secret", "错误密钥不应还原明文")
    return "无填充遇到奇数字节被拒绝；使用错误密钥得到乱码而非原文"


# ---------------------------------------------------------------- 第 4 关
def _double_encryption() -> str:
    rng = random.Random(SEED + 4)
    for _ in range(300):
        plaintext, key = rng.getrandbits(16), rng.getrandbits(32)
        cipher = multiple.double_encrypt(plaintext, key)
        _require(cipher == core.encrypt_block(core.encrypt_block(plaintext, key >> 16), key & 0xFFFF), "双重加密定义不符")
        _require(multiple.double_decrypt(cipher, key) == plaintext, "双重解密未还原")
        _require(multiple.double_encrypt(plaintext, key, IMPLEMENTATIONS["B"]) == cipher, "实现 B 结果不同")
    return "300 组随机 (P, K1‖K2)：C = E_K2(E_K1(P))，解密还原，实现 B 结果相同"


def _triple_encryption() -> str:
    rng = random.Random(SEED + 5)
    for mode, width in multiple.TRIPLE_MODES.items():
        for _ in range(200):
            plaintext, key = rng.getrandbits(16), rng.getrandbits(width)
            cipher = multiple.triple_encrypt(plaintext, key, mode)
            _require(multiple.triple_decrypt(cipher, key, mode) == plaintext, f"{mode} 未还原")
            _require(multiple.triple_encrypt(plaintext, key, mode, IMPLEMENTATIONS["C"]) == cipher, f"{mode} 实现 C 结果不同")
    degenerate = (0x1234 << 16) | 0x1234  # K1 = K2：EDE2 退化为单次加密
    _require(multiple.triple_encrypt(0xBEEF, degenerate, "ede2") == core.encrypt_block(0xBEEF, 0x1234), "K1=K2 应退化为单重")
    return "EDE2（32 位）与 EDE3（48 位）各 200 组往返还原；K1=K2 时 EDE2 退化为单重加密"


def _meet_in_the_middle() -> str:
    example = mitm_example(3, SEED + 6)
    result = mitm_experiment(example["pairs"], example["key"])
    counts = result["counts"]
    _require(result["secret_found"] and result["unique"], f"三对明密文应唯一确定密钥，候选数 {counts}")
    return (f"3 对明密文：候选数 {counts[0]} → {counts[1]} → {counts[2]}，唯一密钥 {hex_text(example['key'], 32)}；"
            f"{result['block_operations']} 次分组运算，耗时 {result['elapsed_ms']:.0f} ms，"
            f"约为穷举 2³² 次的 1/{result['speedup']:.0f}")


# ---------------------------------------------------------------- 第 5 关
def _cbc_roundtrip() -> str:
    rng = random.Random(SEED + 7)
    for _ in range(100):
        message = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 40)))
        key, iv = rng.getrandbits(16), modes.random_iv()
        for padding in ("zero", "pkcs7"):
            if padding == "zero" and message.endswith(b"\x00"):
                continue  # zero 填充无法区分明文结尾自带的 0x00
            blocks = modes.cbc_encrypt_bytes(message, key, iv, padding)
            _require(modes.cbc_decrypt_bytes(blocks, key, iv, padding) == message, f"{padding} 填充的 CBC 未还原")
    return "100 条随机长度消息 × 2 种填充：CBC 加密再解密均还原"


def _cbc_hides_repetition() -> str:
    message = b"A" * 16
    ecb = modes.ecb_encrypt(message, KNOWN_KEY)
    cbc = modes.cbc_encrypt_bytes(message, KNOWN_KEY, 0x1234)
    _require(len(set(ecb)) == 1 and len(set(cbc)) == len(cbc), "ECB 应重复而 CBC 不应重复")
    return "相同的 8 个明文分组：ECB 密文只有 1 种取值，CBC 密文 8 个分组互不相同"


def _cbc_tamper() -> str:
    message = "CBC mode: tamper with one ciphertext block and compare.".encode()
    result = cbc_tamper_experiment(message, KNOWN_KEY, 0x1234, {"type": "flip", "index": 3, "bit": 5})
    rows = result["rows"]
    statuses = [row["status"] for row in rows]
    _require(statuses[3] == "garbled" and statuses.count("garbled") == 1, "被改分组对应的明文应变乱码")
    _require(statuses[4] == "bitflip" and rows[4]["prediction_matches"], "下一个分组应按 C_i ⊕ C'_i 被翻转")
    _require(all(status == "intact" for index, status in enumerate(statuses) if index not in (3, 4)), "其余分组应不受影响")
    return (f"翻转第 4 个密文分组的 1 位：明文第 4 块变乱码、第 5 块恰好被翻转 {int(rows[4]['predicted_difference'], 2):04X}"
            f"（= C₄ ⊕ C′₄），其余 {len(rows) - 2} 块不变")


def _cbc_iv_sharing() -> str:
    message = b"initial vector must be shared!!"
    blocks = modes.cbc_encrypt_bytes(message, KNOWN_KEY, 0x1234)
    wrong = modes.cbc_decrypt_blocks(blocks, KNOWN_KEY, 0x1234 ^ 0x0001)
    right = modes.cbc_decrypt_blocks(blocks, KNOWN_KEY, 0x1234)
    _require(wrong[0] != right[0] and wrong[1:] == right[1:], "错误 IV 只应影响第 1 个明文分组")
    _require(modes.cbc_encrypt_bytes(message, KNOWN_KEY, 0x1234 ^ 1) != blocks, "不同 IV 应得到不同密文")
    return "使用错误 IV 解密：只有第 1 个明文分组出错，其余分组正确；不同 IV 得到不同密文"


LEVELS = {
    1: [("教材示例 · 密钥扩展 2D55", _textbook_key_expansion), ("教材示例 · 半字节代替", _textbook_substitution),
        ("教材示例 · 行移位", _textbook_shift_rows), ("教材示例 · 列混淆与逆列混淆", _textbook_mix_columns),
        ("教材示例 · 轮密钥加", _textbook_add_key), ("GF(2⁴) 乘法两种算法一致", _gf_table),
        ("已知向量 6F6B / A73B → 0738", _known_vector), ("逆运算互逆（全部 65536 个状态）", _inverse_operations),
        ("2000 组随机明密钥往返", _random_roundtrip()), ("固定密钥下加密是排列", _permutation_property),
        ("图解 13 步与真实计算一致", _visual_trace_consistency)],
    2: [("三种实现对已知向量一致", _implementations_known_vector),
        ("组内互验：A/B/C 600 组随机 3×3 交叉", _group_simulation()),
        ("组间模拟：A 组 ↔ B 组（实现 A ↔ C）", _peer_simulation), ("交换文件：导出 → 核验 → 篡改检出", _exchange_roundtrip),
        ("交换文件：算法约定不同被拒绝", _exchange_convention_mismatch), ("纯文本向量导入", _text_vector_lines)],
    3: [("字符串往返（含空串、换行、中文）", _text_roundtrip), ("分组规则：2 字节一组、高字节在前", _text_known_blocks),
        ("跨实现：A 加密 / B 解密 / C 同密文", _text_cross_implementation), ("边界：无填充奇数字节、错误密钥", _text_edge_cases)],
    4: [("双重加密 32 位密钥", _double_encryption), ("三重加密 EDE2 / EDE3", _triple_encryption),
        ("中间相遇攻击找回密钥", _meet_in_the_middle)],
    5: [("CBC 加解密往返", _cbc_roundtrip), ("CBC 隐藏重复分组（对比 ECB）", _cbc_hides_repetition),
        ("篡改密文分组后的解密对比", _cbc_tamper), ("初始向量必须双方共享", _cbc_iv_sharing)],
}


def run_level(level: int) -> dict:
    if level not in LEVELS:
        raise ValueError("关卡编号只能是 1–5")
    started = perf_counter_ns()
    checks = [_run(name, check) for name, check in LEVELS[level]]
    return {"level": level, "title": LEVEL_TITLES[level], "passed": all(item["passed"] for item in checks),
            "checks": checks, "elapsed_ms": (perf_counter_ns() - started) / 1e6}


def run_all() -> dict:
    levels = [run_level(level) for level in LEVELS]
    return {"passed": all(item["passed"] for item in levels), "levels": levels,
            "passed_levels": sum(item["passed"] for item in levels), "total_levels": len(levels),
            "elapsed_ms": sum(item["elapsed_ms"] for item in levels)}
