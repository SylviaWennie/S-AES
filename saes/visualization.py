"""可视化数据模型：每一步都携带实际输入、输出和中间运算，前端只负责绘图与播放。

步骤顺序：1 个数据结构步骤（图 D.2）+ 4 个密钥扩展步骤（图 D.5）+ 8 个加密或解密步骤（图 D.1、D.3、D.4）。
"""

from . import core, gf16
from .formats import bits, validate_integer
from .implementations import IMPLEMENTATIONS, get_implementation

MAX_ROWS = 256
MAX_GROUP_SAMPLE = 4096

# 操作名 -> (教材缩写, 中文名, 说明)
OPERATION_TEXT = {
    "add_key": ("A_K", "轮密钥加", "状态与轮密钥逐位异或。异或是自身的逆运算，所以加密和解密使用同一个函数。"),
    "substitute": ("NS", "半字节代替", "每个半字节：左 2 位当行号、右 2 位当列号，查 S 盒（表 D.1(a)）。"),
    "inv_substitute": ("INS", "逆半字节代替", "行列取法相同，但查逆 S 盒（表 D.1(b)）。"),
    "shift_rows": ("SR", "行移位", "第一行不变，第二行的两个半字节互换（循环移动一个半字节）。"),
    "inv_shift_rows": ("ISR", "逆行移位", "把第二行移回原位，与行移位完全相同。"),
    "mix_columns": ("MC", "列混淆", "状态矩阵左乘 [[1,4],[4,1]]：加法是异或，乘法在 GF(2⁴) 上进行（模 x⁴+x+1）。"),
    "inv_mix_columns": ("IMC", "逆列混淆", "状态矩阵左乘 [[9,2],[2,9]]，它是 [[1,4],[4,1]] 在 GF(2⁴) 上的逆矩阵。"),
}
ENCRYPT_GROUPS = ("pre", "round1", "round1", "round1", "round1", "round2", "round2", "round2")
DECRYPT_GROUPS = ("pre", "round1", "round1", "round1", "round1", "round2", "round2", "post")
GROUP_ROUND = {"pre": 0, "round1": 1, "round2": 2, "post": 2}
GROUP_TITLE = {False: {"pre": "第 0 轮", "round1": "第 1 轮", "round2": "第 2 轮"},
               True: {"pre": "解密起始", "round1": "解密第 1 轮", "round2": "解密第 2 轮", "post": "解密收尾"}}


def _sbox_lookups(nibbles: tuple[int, ...], box: tuple[int, ...]) -> list[dict]:
    return [{"position": position, "input": value, "row": value >> 2, "column": value & 3, "output": box[value]}
            for position, value in enumerate(nibbles)]


def _describe_mix(before: int, matrix: tuple) -> dict:
    nibbles = core.split_nibbles(before)
    terms = []
    for position in range(4):
        column, row = divmod(position, 2)  # 位置 N0,N1,N2,N3 = 第 0 列的两行、第 1 列的两行
        parts = []
        for index in range(2):
            source = 2 * column + index
            product = gf16.describe_product(matrix[row][index], nibbles[source])
            parts.append({"coefficient": matrix[row][index], "source": source, "value": nibbles[source],
                          "product": product["value"], "text": product["text"]})
        terms.append({"position": position, "parts": parts, "result": parts[0]["product"] ^ parts[1]["product"]})
    return {"matrix": [list(row) for row in matrix], "terms": terms}


def _describe_operation(operation: str, before: int, key: int | None, key_name: str | None) -> dict:
    if operation == "add_key":
        return {"key": key, "key_name": key_name,
                "xor": [{"position": position, "state": state, "key": part, "result": state ^ part}
                        for position, (state, part) in enumerate(zip(core.split_nibbles(before), core.split_nibbles(key)))]}
    if operation in ("substitute", "inv_substitute"):
        box = core.SBOX if operation == "substitute" else core.INV_SBOX
        return {"table": list(box), "lookups": _sbox_lookups(core.split_nibbles(before), box)}
    if operation in ("shift_rows", "inv_shift_rows"):
        return {"mapping": [0, 3, 2, 1]}  # 输出位置 i 取输入位置 mapping[i]
    matrix = core.MIX_MATRIX if operation == "mix_columns" else core.INV_MIX_MATRIX
    return _describe_mix(before, matrix)


def _cipher_steps(trace: dict) -> list[dict]:
    decrypt = trace["decrypt"]
    groups = DECRYPT_GROUPS if decrypt else ENCRYPT_GROUPS
    steps = []
    for index, (operation, key_index) in enumerate(trace["plan"]):
        before, after = trace["states"][index], trace["states"][index + 1]
        abbreviation, name, description = OPERATION_TEXT[operation]
        key_name = None if key_index is None else f"K{key_index}"
        group = groups[index]
        label = f"A_{key_name}" if operation == "add_key" else abbreviation
        steps.append({"id": f"{'d' if decrypt else 'e'}{index}-{operation}", "phase": "cipher", "kind": operation,
                      "index": index, "group": group, "round": GROUP_ROUND[group], "label": label,
                      "title": f"{GROUP_TITLE[decrypt][group]} · {label} {name}", "description": description,
                      "before": before, "after": after,
                      **_describe_operation(operation, before, None if key_index is None else trace["round_keys"][key_index], key_name)})
    return steps


def _g_detail(word: int, round_index: int) -> dict:
    rotated = core.rotate_nibbles(word)
    substituted = core.substitute_word(rotated)
    return {"input": word, "rotated": rotated, "substituted": substituted, "round_index": round_index,
            "round_constant": core.ROUND_CONSTANTS[round_index - 1],
            "output": substituted ^ core.ROUND_CONSTANTS[round_index - 1],
            "lookups": _sbox_lookups((rotated >> 4, rotated & 15), core.SBOX)}


def _key_steps(key: int) -> list[dict]:
    w = core.expand_key(key)
    specs = [
        (2, "w2 = w0 ⊕ g(w1)", w[0], w[1], _g_detail(w[1], 1), "g(w1) = SubNib(RotNib(w1)) ⊕ RCON(1)"),
        (3, "w3 = w2 ⊕ w1", w[2], w[1], None, "后一个字直接与前一轮的字异或"),
        (4, "w4 = w2 ⊕ g(w3)", w[2], w[3], _g_detail(w[3], 2), "g(w3) = SubNib(RotNib(w3)) ⊕ RCON(2)"),
        (5, "w5 = w4 ⊕ w3", w[4], w[3], None, "得到第三个轮密钥 K2 = w4w5"),
    ]
    return [{"id": f"kx-w{target}", "phase": "key", "kind": "key_expansion", "target": target,
             "title": f"密钥扩展 · {formula}", "description": note, "known": list(range(target + 1)),
             "left": left, "right": right, "g": g, "result": w[target]}
            for target, formula, left, right, g, note in specs]


def _structure_step(block: int, key: int, decrypt: bool) -> dict:
    return {"id": "structure", "phase": "structure", "kind": "structure", "title": "数据结构 · 状态矩阵与密钥字（图 D.2）",
            "description": "16 位数据按列分成 4 个半字节排进 2×2 状态矩阵；16 位密钥分成两个 8 位字 w0、w1。",
            "block": block, "key": key, "block_name": "密文" if decrypt else "明文"}


def visual_trace(block: int, key: int, operation: str = "encrypt") -> dict:
    """生成按真实计算顺序排列的 13 个图解步骤，并附带反方向的还原检查。"""
    validate_integer(block, 16, "分组")
    validate_integer(key, 16, "密钥")
    if operation not in ("encrypt", "decrypt"):
        raise ValueError("请选择加密或解密")
    decrypt = operation == "decrypt"
    trace = core.trace_block(block, key, decrypt)
    result = trace["result"]
    back = core.decrypt_block(result, key) if not decrypt else core.encrypt_block(result, key)
    return {"mode": operation, "spec_id": core.SPEC_ID, "input": block, "key": key, "result": result,
            "words": list(trace["words"]), "round_keys": list(trace["round_keys"]), "states": trace["states"],
            "steps": [_structure_step(block, key, decrypt), *_key_steps(key), *_cipher_steps(trace)],
            "roundtrip": {"operation": "decrypt" if not decrypt else "encrypt", "input": result,
                          "result": back, "matches": back == block}}


def _implementation_notes() -> list[dict]:
    return [{"key": item.key, "name": item.name, "style": item.style} for item in IMPLEMENTATIONS.values()]


def reference_tables() -> dict:
    """S 盒、逆 S 盒、GF(2⁴) 乘法表等常量，来自核心实现本身，用于「原理速查」。"""
    return {"spec_id": core.SPEC_ID, "sbox": list(core.SBOX), "inv_sbox": list(core.INV_SBOX),
            "mix_matrix": [list(row) for row in core.MIX_MATRIX], "inv_mix_matrix": [list(row) for row in core.INV_MIX_MATRIX],
            "round_constants": list(core.ROUND_CONSTANTS), "modulus": gf16.MODULUS,
            "multiplication": [[gf16.multiply(a, b) for b in range(16)] for a in range(16)],
            "implementations": _implementation_notes()}


def simulate_group(key: int, plaintexts: list[int]) -> dict:
    """组内测试：A、B、C 三种独立实现对同一批明文加密，再 3×3 交叉解密。个人模拟，不代表真人互测。"""
    validate_integer(key, 16, "密钥")
    if not isinstance(plaintexts, list) or not 1 <= len(plaintexts) <= MAX_GROUP_SAMPLE:
        raise ValueError(f"组内互验需要 1–{MAX_GROUP_SAMPLE} 条明文")
    implementations = list(IMPLEMENTATIONS.values())
    rows = []
    for plaintext in plaintexts:
        validate_integer(plaintext, 16, "明文")
        ciphertexts = {item.key: item.encrypt(plaintext, key) for item in implementations}
        crosses = [{"from": sender.key, "to": receiver.key,
                    "ok": receiver.decrypt(ciphertexts[sender.key], key) == plaintext}
                   for sender in implementations for receiver in implementations]
        equal = len(set(ciphertexts.values())) == 1
        rows.append({"plaintext": bits(plaintext), "ciphertexts": {name: bits(value) for name, value in ciphertexts.items()},
                     "equal": equal, "cross": crosses, "ok": equal and all(item["ok"] for item in crosses)})
    counts = {"encrypt_equal": sum(row["equal"] for row in rows),
              "cross_decrypt_ok": sum(item["ok"] for row in rows for item in row["cross"]),
              "cross_decrypt_total": 9 * len(rows)}
    return {"simulation": True, "scope": "group", "spec_id": core.SPEC_ID, "key": bits(key),
            "implementations": _implementation_notes(),
            "notice": "个人在本机用三种结构不同的实现模拟组内三位成员；这是实际程序互测，没有其他同学参与。",
            "passed": counts["encrypt_equal"] == len(rows) and counts["cross_decrypt_ok"] == counts["cross_decrypt_total"],
            "total": len(rows), "counts": counts, "rows": rows[:MAX_ROWS], "rows_shown": min(len(rows), MAX_ROWS)}


def _transfer_frames(sender, receiver, plaintext: str, ciphertext: str, decoded: str) -> list[dict]:
    return [{"title": f"{sender.key} 组加密", "actor": sender.key, "operation": "encrypt", "input": plaintext,
             "output": ciphertext, "description": f"{sender.key} 组用共享密钥加密 16 位明文（{sender.name}）。"},
            {"title": f"模拟信道 · {sender.key} → {receiver.key}", "actor": "channel", "operation": "transfer",
             "input": ciphertext, "output": ciphertext, "description": "本地模拟传递密文，没有发送到网络或其他同学。"},
            {"title": f"{receiver.key} 组解密", "actor": receiver.key, "operation": "decrypt", "input": ciphertext,
             "output": decoded, "description": f"{receiver.key} 组用自己的实现（{receiver.name}）解密，核对是否等于原明文。"}]


def simulate_peers(key: int, plaintexts: list[int], group_a: str = "A", group_b: str = "C") -> dict:
    """组间测试：同一密钥下，A 组、B 组各用一种实现，比较密文并双向传递解密。"""
    validate_integer(key, 16, "密钥")
    if not isinstance(plaintexts, list) or not 1 <= len(plaintexts) <= MAX_ROWS:
        raise ValueError(f"组间模拟需要 1–{MAX_ROWS} 条明文")
    side_a, side_b = get_implementation(group_a), get_implementation(group_b)
    rows = []
    for plaintext in plaintexts:
        validate_integer(plaintext, 16, "明文")
        a_cipher, b_cipher = side_a.encrypt(plaintext, key), side_b.encrypt(plaintext, key)
        b_decrypted, a_decrypted = side_b.decrypt(a_cipher, key), side_a.decrypt(b_cipher, key)
        rows.append({"plaintext": bits(plaintext), "key": bits(key), "a_ciphertext": bits(a_cipher),
                     "b_ciphertext": bits(b_cipher), "b_decrypted": bits(b_decrypted), "a_decrypted": bits(a_decrypted),
                     "encrypt_equal": a_cipher == b_cipher, "a_to_b_ok": b_decrypted == plaintext,
                     "b_to_a_ok": a_decrypted == plaintext})
    counts = {name: sum(row[name] for row in rows) for name in ("encrypt_equal", "a_to_b_ok", "b_to_a_ok")}
    example = rows[0]
    return {"simulation": True, "scope": "peers", "spec_id": core.SPEC_ID, "key": bits(key),
            "group_a": {"key": side_a.key, "name": side_a.name}, "group_b": {"key": side_b.key, "name": side_b.name},
            "notice": "个人完成的双实现模拟实验；未进行真人跨组测试，不冒充小组实验结果。",
            "passed": all(value == len(rows) for value in counts.values()), "total": len(rows), "rows": rows,
            "counts": counts,
            "demo": {"plaintext": example["plaintext"], "key": example["key"], "ciphertext": example["a_ciphertext"],
                     "a_to_b": _transfer_frames(side_a, side_b, example["plaintext"], example["a_ciphertext"], example["b_decrypted"]),
                     "b_to_a": _transfer_frames(side_b, side_a, example["plaintext"], example["b_ciphertext"], example["a_decrypted"])}}
