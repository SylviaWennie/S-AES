"""第 4、5 关的实验：中间相遇攻击示例、CBC 篡改密文对比。"""

import random

from . import multiple
from .formats import bits, hex_text, validate_integer
from .implementations import DEFAULT, Implementation
from .modes import (blocks_to_bytes, bytes_to_blocks, bytes_to_text, cbc_decrypt_blocks, cbc_encrypt_blocks,
                    ecb_encrypt, pad, printable_view, unpad)

TAMPER_TYPES = ("replace", "flip", "set", "swap")


def mitm_example(pair_count: int = 3, seed: int | None = None) -> dict:
    """随机选一把 32 位双重密钥，生成 pair_count 对明密文；seed 固定时结果可复现。"""
    if not 1 <= pair_count <= 16:
        raise ValueError("明密文对数应在 1–16 之间")
    rng = random.Random(seed)
    key = rng.getrandbits(32)
    plaintexts = rng.sample(range(1 << 16), pair_count)
    return {"key": key, "pairs": [(plaintext, multiple.double_encrypt(plaintext, key)) for plaintext in plaintexts]}


def mitm_experiment(pairs: list[tuple[int, int]], secret_key: int | None = None, listed: int = 32) -> dict:
    """运行中间相遇攻击，并把候选数收敛过程、耗时与穷举估算整理成可展示的结果。"""
    attack = multiple.meet_in_the_middle(pairs)
    estimate = multiple.estimate_exhaustive_seconds()
    candidates = attack["candidates"]
    return {"pairs": [{"plaintext": bits(p), "ciphertext": bits(c)} for p, c in pairs],
            "counts": attack["counts"], "candidate_total": len(candidates),
            "candidates": [{"key": bits(key, 32), "hex": hex_text(key, 32)} for key in candidates[:listed]],
            "listed": min(listed, len(candidates)), "block_operations": attack["block_operations"],
            "table_entries": attack["table_entries"], "table_ms": attack["table_ms"], "elapsed_ms": attack["elapsed_ms"],
            "exhaustive_operations": estimate["exhaustive_operations"],
            "exhaustive_estimate_seconds": estimate["estimated_seconds"],
            "per_operation_us": estimate["per_operation_us"],
            "speedup": estimate["exhaustive_operations"] / attack["block_operations"],
            "secret_found": None if secret_key is None else secret_key in candidates,
            "unique": len(candidates) == 1}


def tamper_blocks(blocks: list[int], action: dict) -> list[int]:
    """对密文分组做替换 / 修改。action: {type, index, other?, bit?, value?}，下标从 0 开始。"""
    kind, index = action.get("type"), action.get("index")
    if kind not in TAMPER_TYPES:
        raise ValueError("篡改方式只能是 replace、flip、set 或 swap")
    if type(index) is not int or not 0 <= index < len(blocks):
        raise ValueError(f"分组序号必须在 0 到 {len(blocks) - 1} 之间")
    result = list(blocks)
    if kind in ("replace", "swap"):
        other = action.get("other")
        if type(other) is not int or not 0 <= other < len(blocks):
            raise ValueError(f"另一个分组序号必须在 0 到 {len(blocks) - 1} 之间")
        result[index] = blocks[other]
        if kind == "swap":
            result[other] = blocks[index]
    elif kind == "flip":
        bit = action.get("bit")
        if type(bit) is not int or not 0 <= bit < 16:
            raise ValueError("要翻转的位序号必须在 0 到 15 之间（b0 是最高位）")
        result[index] = blocks[index] ^ (0x8000 >> bit)
    else:
        result[index] = validate_integer(action.get("value"), 16, "自定义密文")
    return result


def _lenient_unpad(data: bytes, padding: str) -> tuple[bytes, bool]:
    """篡改后的明文可能不再满足填充格式：此时保留原始字节，并标记填充已损坏。"""
    try:
        return unpad(data, padding), False
    except ValueError:
        return data, True


def cbc_tamper_experiment(plaintext: bytes, key: int, iv: int, action: dict, padding: str = "zero",
                          cipher: Implementation = DEFAULT) -> dict:
    """CBC 加密后篡改一个密文分组再解密，逐块对比篡改前后的明文。

    P'_i = D(C'_i) ⊕ C'_{i-1}：被改的密文分组 i 对应的明文整块变成乱码；
    下一个分组 i+1 只受 C'_i 影响，明文与原文相差恰好是 C_i ⊕ C'_i（可预测的位翻转）；其余分组不受影响。
    """
    plain_blocks = bytes_to_blocks(pad(plaintext, padding))
    cipher_blocks = cbc_encrypt_blocks(plain_blocks, key, iv, cipher)
    tampered = tamper_blocks(cipher_blocks, action)
    recovered_original = cbc_decrypt_blocks(cipher_blocks, key, iv, cipher)
    recovered_tampered = cbc_decrypt_blocks(tampered, key, iv, cipher)
    changed = {index for index, (before, after) in enumerate(zip(cipher_blocks, tampered)) if before != after}
    rows = []
    for index, (original, now) in enumerate(zip(recovered_original, recovered_tampered)):
        if index in changed:
            status = "garbled" if now != original else "intact"
            expected = None
        elif index - 1 in changed:
            expected = cipher_blocks[index - 1] ^ tampered[index - 1]
            status = "bitflip" if now != original else "intact"
        else:
            status, expected = "intact", None
        difference = original ^ now
        rows.append({"index": index, "status": status, "cipher": bits(cipher_blocks[index]),
                     "tampered_cipher": bits(tampered[index]), "cipher_changed": index in changed,
                     "plain": bits(original), "recovered": bits(now), "xor_difference": bits(difference),
                     "predicted_difference": None if expected is None else bits(expected),
                     "prediction_matches": expected is not None and expected == difference,
                     "plain_text": printable_view(original.to_bytes(2, "big")),
                     "recovered_text": printable_view(now.to_bytes(2, "big"))})
    before_bytes, _ = _lenient_unpad(blocks_to_bytes(recovered_original), padding)
    after_bytes, padding_broken = _lenient_unpad(blocks_to_bytes(recovered_tampered), padding)
    return {"iv": bits(iv), "action": action, "block_count": len(plain_blocks),
            "plain_blocks": [bits(block) for block in plain_blocks],
            "cipher_blocks": [bits(block) for block in cipher_blocks],
            "tampered_blocks": [bits(block) for block in tampered],
            "ecb_blocks": [bits(block) for block in ecb_encrypt(plaintext, key, padding, cipher)],
            "rows": rows, "changed_cipher_blocks": sorted(changed),
            "original_text": bytes_to_text(before_bytes), "tampered_text": bytes_to_text(after_bytes),
            "padding_broken": padding_broken,
            "summary": {status: sum(row["status"] == status for row in rows) for status in ("intact", "garbled", "bitflip")}}
