"""与另一小组公开提交的 S-AES 实现做组间互测（第 1–5 关），保存原始数据并生成 docs/cross-test-report.md。

用法（仓库根目录）：
    python scripts/cross_test_peer.py --peer-dir <对方仓库的克隆目录>
    python scripts/cross_test_peer.py --render-only      # 不重跑，只根据已保存的 JSON 重新生成文档

对方代码只按文件路径加载，不复制进本仓库，也不修改；加载时关闭字节码缓存，不会往对方目录写文件。
随机数使用固定种子，结果可复现。全空间对照约需 1–2 分钟。
输出：reports/cross-test-<对方标识>.json、examples/peer-<对方标识>-vectors.txt、docs/cross-test-report.md。
"""

import argparse
import difflib
import hashlib
import importlib.util
import json
import platform
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from saes import core, exchange, modes, multiple  # noqa: E402
from saes.formats import hex_text, parse_value  # noqa: E402
from saes.implementations import IMPLEMENTATIONS  # noqa: E402

PEER_ID = "anxayh"
PEER_REPO = "https://github.com/Anxayh/S-AES_Assignment"
SEED = 20261030
H = hex_text

FIXED_KEYS = (0x4AF5, 0x2D55, 0xA73B, 0x0000, 0xFFFF, 0x8000, 0x0001, 0x9C1E)
FIXED_PLAINTEXTS = (0xD728, 0x6F6B, 0xA749, 0x0000, 0xFFFF, 0x8000, 0x0001, 0x5A5A)
EDGE_PAIRS = ((0x0000, 0x0000), (0xFFFF, 0xFFFF), (0x0000, 0xFFFF), (0xFFFF, 0x0000), (0x8000, 0x0001))
BASIC_VECTORS = (
    ("对方文档 `外部交叉测试向量.md`", 0xD728, 0x4AF5, 0x24EC),
    ("我方 `examples/vectors.txt`", 0x6F6B, 0xA73B, 0x0738),
    ("教材 D.2 示例所用的明文和密钥（密文由我方实现算出）", 0xA749, 0x2D55, 0xC349),
)
ERROR_LIMIT = 5  # 每组对照最多保存的不一致样例数


# ------------------------------------------------------------------ 载入与小工具
def load_peer(peer_dir: Path, module_name: str = "saes_core"):
    """按路径载入对方的核心模块，默认登记为 saes_core，供之后载入对方的 app.py 时使用。"""
    spec = importlib.util.spec_from_file_location(module_name, peer_dir / "saes_core.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_git(directory: Path, *arguments: str) -> str:
    result = subprocess.run(["git", "-C", str(directory), *arguments], capture_output=True, text=True, encoding="utf-8")
    return result.stdout.strip()


def outcome(function) -> tuple:
    """('ok', 结果) 或 ('error', 异常类型名)，便于比较两端对同一输入的反应。"""
    try:
        return ("ok", function())
    except Exception as error:  # noqa: BLE001 - 黑盒测试需要捕获对方抛出的任何异常
        return ("error", type(error).__name__)


def timed(function):
    started = time.perf_counter()
    result = function()
    return result, (time.perf_counter() - started) * 1000


def require_in_document(text: str, tokens: list[str], name: str) -> None:
    """硬编码的期望值必须真的出现在对方文档里，避免抄错或凭印象。"""
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{name} 中找不到预期的内容：{missing}")


def extract(text: str, pattern: str) -> str:
    found = re.search(pattern, text)
    if not found:
        raise SystemExit(f"对方文档中找不到：{pattern}")
    return found.group(1)


def hex_bytes(data: bytes) -> str:
    return data.hex(" ").upper()


# ------------------------------------------------------------------ 第 1、2 关：单分组
def block_agreement(peer, plaintext: int, key: int) -> tuple[bool, bool, bool]:
    """(密文一致, 我方密文由对方解密还原, 对方密文由我方解密还原)。"""
    ours = core.encrypt_block(plaintext, key)
    theirs = peer.encrypt_block(plaintext, key)
    return ours == theirs, peer.decrypt_block(ours, key) == plaintext, core.decrypt_block(theirs, key) == plaintext


def sweep(peer, pairs) -> dict:
    counts = {"total": 0, "same_ciphertext": 0, "ours_to_peer": 0, "peer_to_ours": 0, "mismatches": []}
    for plaintext, key in pairs:
        same, forward, backward = block_agreement(peer, plaintext, key)
        counts["total"] += 1
        counts["same_ciphertext"] += same
        counts["ours_to_peer"] += forward
        counts["peer_to_ours"] += backward
        if not (same and forward and backward) and len(counts["mismatches"]) < ERROR_LIMIT:
            counts["mismatches"].append({"plaintext": H(plaintext), "key": H(key)})
    return counts


def collect_level1(peer) -> dict:
    rows = []
    for source, plaintext, key, expected in BASIC_VECTORS:
        ours, theirs = core.encrypt_block(plaintext, key), peer.encrypt_block(plaintext, key)
        rows.append({"source": source, "plaintext": H(plaintext), "key": H(key), "expected": H(expected),
                     "ours": H(ours), "peer": H(theirs), "peer_decrypts_ours": H(peer.decrypt_block(ours, key)),
                     "ours_decrypts_peer": H(core.decrypt_block(theirs, key)),
                     "ok": ours == theirs == expected and peer.decrypt_block(ours, key) == plaintext
                     and core.decrypt_block(theirs, key) == plaintext})
    edge = sweep(peer, EDGE_PAIRS)
    return {"vectors": rows, "edge": edge}


def collect_level2(peer, claims_text: str, rng: random.Random) -> dict:
    expansion_mismatches = [key for key in range(1 << 16) if tuple(peer.expand_key(key)) != tuple(core.round_keys(key))]
    plaintext_space = {H(key): sweep(peer, ((plaintext, key) for plaintext in range(1 << 16))) for key in FIXED_KEYS}
    key_space = {H(plaintext): sweep(peer, ((plaintext, key) for key in range(1 << 16))) for plaintext in FIXED_PLAINTEXTS}
    random_pairs = [(rng.randrange(1 << 16), rng.randrange(1 << 16)) for _ in range(1 << 16)]
    random_sweep = sweep(peer, random_pairs)

    require_in_document(claims_text, ["P=D728", "K=4AF5", "C=24EC", "2D55", "BCE9", "A34A"], "外部交叉测试向量.md")
    document_claims = [
        {"claim": "P=D728, K=4AF5 → C=24EC", "ours": H(core.encrypt_block(0xD728, 0x4AF5)), "expected": "24EC"},
        {"claim": "C=24EC, K=4AF5 → P=D728", "ours": H(core.decrypt_block(0x24EC, 0x4AF5)), "expected": "D728"},
        {"claim": "密钥扩展 2D55 → K1=BCE9", "ours": H(core.round_keys(0x2D55)[1]), "expected": "BCE9"},
        {"claim": "密钥扩展 2D55 → K2=A34A", "ours": H(core.round_keys(0x2D55)[2]), "expected": "A34A"},
    ]

    # 交换文件：对方实现生成 256 条「明文 密钥 密文」，由我方的交换文件工具核验
    vector_pairs = [(0xD728, 0x4AF5)] + [(rng.randrange(1 << 16), rng.randrange(1 << 16)) for _ in range(255)]
    lines = [f"# 由对方 {PEER_REPO} 的 saes_core.encrypt_block 生成的 256 条向量（每行：明文 密钥 密文，十六进制）",
             "# 用 python -m saes verify examples/peer-anxayh-vectors.txt 核验；第一条是对方文档中的固定向量"]
    lines += [f"{H(p)} {H(k)} {H(peer.encrypt_block(p, k))}" for p, k in vector_pairs]
    text = "\n".join(lines) + "\n"
    verified = {key: exchange.verify_vectors(exchange.parse_vector_lines(text), implementation)
                for key, implementation in IMPLEMENTATIONS.items()}
    return {"key_expansion": {"total": 1 << 16, "mismatches": len(expansion_mismatches), "examples": [H(k) for k in expansion_mismatches[:ERROR_LIMIT]]},
            "plaintext_space": plaintext_space, "key_space": key_space, "random": random_sweep,
            "document_claims": document_claims,
            "vector_file": {"text": text, "count": len(vector_pairs),
                            "verified": {key: {"passed": v["passed"], "total": v["total"], "encrypt": v["encrypt_passed"], "decrypt": v["decrypt_passed"]}
                                         for key, v in verified.items()}}}


# ------------------------------------------------------------------ 第 3 关：ASCII
def ascii_corpus(rng: random.Random) -> list[tuple[str, int]]:
    fixed = ["S-AES", "Hello, S-AES!", "AB", "A", "", "ABABABAB", "The quick brown fox jumps over the lazy dog.", "0123456789", " ", "~!@#$%^&*()_+"]
    printable = [chr(code) for code in range(0x20, 0x7F)]
    randoms = ["".join(rng.choice(printable) for _ in range(rng.randrange(0, 34))) for _ in range(300)]
    return [(text, rng.randrange(1 << 16)) for text in fixed + randoms]


def collect_level3(peer, results_text: str, rng: random.Random) -> dict:
    same = forward = backward = total = 0
    mismatches = []
    for text, key in ascii_corpus(rng):
        data = text.encode("ascii")
        ours = modes.blocks_to_bytes(modes.ecb_encrypt(data, key, "zero"))
        theirs, length = peer.encrypt_ascii(text, key)
        ours_ok = ours == theirs
        peer_reads_ours = peer.decrypt_ascii(ours, key, len(data)) == data
        ours_reads_peer = modes.ecb_decrypt(modes.bytes_to_blocks(theirs), key, "zero") == data
        total += 1
        same, forward, backward = same + ours_ok, forward + peer_reads_ours, backward + ours_reads_peer
        if not (ours_ok and peer_reads_ours and ours_reads_peer and length == len(data)) and len(mismatches) < ERROR_LIMIT:
            mismatches.append({"text": text, "key": H(key)})

    claimed = extract(results_text, r"密文 bytes：`([0-9A-F ]+)`")
    ours_claim = hex_bytes(modes.blocks_to_bytes(modes.ecb_encrypt(b"S-AES", 0x4AF5, "zero")))

    nul_text = "A\x00"
    nul_ours = modes.ecb_decrypt(modes.ecb_encrypt(nul_text.encode(), 0x4AF5, "zero"), 0x4AF5, "zero")
    nul_peer_cipher, nul_length = peer.encrypt_ascii(nul_text, 0x4AF5)
    nul_peer = peer.decrypt_ascii(nul_peer_cipher, 0x4AF5, nul_length)
    non_ascii_text = "信息安全"
    return {"total": total, "same_ciphertext": same, "ours_to_peer": forward, "peer_to_ours": backward, "mismatches": mismatches,
            "document_claim": {"claim": "S-AES / 4AF5 的密文字节", "peer_document": claimed, "ours": ours_claim, "ok": claimed == ours_claim},
            "trailing_nul": {"text_hex": hex_bytes(nul_text.encode()), "ours_zero_padding_recovers": hex_bytes(nul_ours), "peer_recovers": hex_bytes(nul_peer)},
            "non_ascii": {"text": non_ascii_text, "peer": outcome(lambda: peer.encrypt_ascii(non_ascii_text, 0x4AF5)[0].hex())[0:2],
                          "ours": hex_bytes(modes.blocks_to_bytes(modes.ecb_encrypt(modes.text_to_bytes(non_ascii_text), 0x4AF5, "zero")))}}


# ------------------------------------------------------------------ 第 4 关：多重加密与中间相遇
def pack(*keys: int) -> int:
    value = 0
    for key in keys:
        value = (value << 16) | key
    return value


def collect_level4(peer, claims_text: str, results_text: str, rng: random.Random) -> dict:
    cases = [(rng.randrange(1 << 16), rng.randrange(1 << 16), rng.randrange(1 << 16), rng.randrange(1 << 16)) for _ in range(2000)]
    double = {"total": 0, "same": 0, "ours_to_peer": 0, "peer_to_ours": 0}
    ede2 = {"total": 0, "same": 0, "ours_to_peer": 0, "peer_to_ours": 0}
    triple48 = {"total": 0, "peer_eee_equals_ours_ede3": 0, "peer_eee_equals_composed_ours": 0, "ours_ede3_equals_composed_peer": 0,
                "peer_eee_round_trip_ours": 0}
    for plaintext, key1, key2, key3 in cases:
        key32, key48 = pack(key1, key2), pack(key1, key2, key3)
        ours, theirs = multiple.double_encrypt(plaintext, key32), peer.encrypt_double(plaintext, key1, key2)
        double["total"] += 1
        double["same"] += ours == theirs
        double["ours_to_peer"] += peer.decrypt_double(ours, key1, key2) == plaintext
        double["peer_to_ours"] += multiple.double_decrypt(theirs, key32) == plaintext
        ours, theirs = multiple.triple_encrypt(plaintext, key32, "ede2"), peer.encrypt_triple_ede(plaintext, key1, key2)
        ede2["total"] += 1
        ede2["same"] += ours == theirs
        ede2["ours_to_peer"] += peer.decrypt_triple_ede(ours, key1, key2) == plaintext
        ede2["peer_to_ours"] += multiple.triple_decrypt(theirs, key32, "ede2") == plaintext
        eee_peer = peer.encrypt_triple_eee(plaintext, key1, key2, key3)
        ede3_ours = multiple.triple_encrypt(plaintext, key48, "ede3")
        composed_eee = core.encrypt_block(core.encrypt_block(core.encrypt_block(plaintext, key1), key2), key3)
        composed_ede = peer.encrypt_block(peer.decrypt_block(peer.encrypt_block(plaintext, key1), key2), key3)
        triple48["total"] += 1
        triple48["peer_eee_equals_ours_ede3"] += eee_peer == ede3_ours
        triple48["peer_eee_equals_composed_ours"] += eee_peer == composed_eee
        triple48["ours_ede3_equals_composed_peer"] += ede3_ours == composed_ede
        triple48["peer_eee_round_trip_ours"] += core.decrypt_block(core.decrypt_block(core.decrypt_block(eee_peer, key3), key2), key1) == plaintext

    require_in_document(claims_text, ["88E5", "738D", "5D49", "2D55", "BACE"], "外部交叉测试向量.md")
    claim_rows = []
    for plaintext, expected in ((0x1234, 0x88E5), (0xD728, 0x738D), (0xCAFE, 0x5D49)):
        ours = multiple.double_encrypt(plaintext, pack(0x2D55, 0xBACE))
        claim_rows.append({"plaintext": H(plaintext), "expected": H(expected), "ours": H(ours), "ok": ours == expected})
    eee_claim = extract(results_text, r"48-bit 三密钥 EEE：密文 `([0-9A-F]{4})`")
    ede_claim = extract(results_text, r"32-bit 双密钥 EDE：密文 `([0-9A-F]{4})`")
    claimed = {"ede2": {"peer_document": ede_claim, "ours": H(multiple.triple_encrypt(0x1234, pack(0x2D55, 0xBACE), "ede2"))},
               "eee": {"peer_document": eee_claim, "ours_ede3": H(multiple.triple_encrypt(0x1234, pack(0x2D55, 0xBACE, 0x91E3), "ede3")),
                       "ours_composed_eee": H(core.encrypt_block(core.encrypt_block(core.encrypt_block(0x1234, 0x2D55), 0xBACE), 0x91E3))}}

    mitm_rows = []
    for source in ("peer", "ours"):
        for pair_count in (1, 2, 3):
            key1, key2 = rng.randrange(1 << 16), rng.randrange(1 << 16)
            plaintexts = [rng.randrange(1 << 16) for _ in range(pair_count)]
            encrypt = (lambda p: peer.encrypt_double(p, key1, key2)) if source == "peer" else (lambda p: multiple.double_encrypt(p, pack(key1, key2)))
            pairs = [(p, encrypt(p)) for p in plaintexts]
            theirs, peer_ms = timed(lambda: peer.meet_in_the_middle(pairs))
            ours_result, our_ms = timed(lambda: multiple.meet_in_the_middle(pairs))
            their_set = {pack(a, b) for a, b in theirs}
            our_set = set(ours_result["candidates"])
            mitm_rows.append({"pairs_from": source, "pair_count": pair_count, "true_key": H32(key1, key2), "peer_candidates": len(their_set),
                              "our_candidates": len(our_set), "same_set": their_set == our_set, "contains_true_key": pack(key1, key2) in their_set,
                              "peer_ms": round(peer_ms), "our_ms": round(our_ms)})
    documented_pairs = [(0x1234, 0x88E5), (0xD728, 0x738D), (0xCAFE, 0x5D49)]
    documented = multiple.meet_in_the_middle(documented_pairs)["candidates"]
    peer_documented = peer.meet_in_the_middle(documented_pairs)
    return {"double": double, "ede2": ede2, "triple48": triple48, "document_double": claim_rows, "document_triple": claimed,
            "mitm": mitm_rows, "document_mitm": {"ours": [H32(c >> 16, c & 0xFFFF) for c in documented],
                                                 "peer": [H32(a, b) for a, b in peer_documented]}}


def H32(key1: int, key2: int) -> str:
    return f"{H(key1)}{H(key2)}"


# ------------------------------------------------------------------ 第 5 关：CBC
def our_cbc_encrypt(message: bytes, key: int, iv: int) -> bytes:
    return modes.blocks_to_bytes(modes.cbc_encrypt_bytes(message, key, iv, "pkcs7"))


def our_cbc_decrypt(ciphertext: bytes, key: int, iv: int) -> bytes:
    return modes.cbc_decrypt_bytes(modes.bytes_to_blocks(ciphertext), key, iv, "pkcs7")


def split_blocks(data: bytes) -> list[bytes]:
    return [data[index:index + 2] for index in range(0, len(data), 2)]


def collect_level5(peer, results_text: str, rng: random.Random) -> dict:
    messages = [b"CBC mode: block chaining test."] + [bytes(rng.randrange(0x20, 0x7F) for _ in range(length)) for length in
                                                          (0, 1, 2, 3, 8, 15, 16, 17, 31, 32, 40)] + \
               [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 41))) for _ in range(100)]
    same = forward = backward = total = 0
    mismatches = []
    for message in messages:
        key, iv = rng.randrange(1 << 16), rng.randrange(1 << 16)
        used_iv, theirs = peer.cbc_encrypt(message, key, iv)
        ours = our_cbc_encrypt(message, key, iv)
        flags = (used_iv == iv and ours == theirs, peer.cbc_decrypt(ours, key, iv) == message, our_cbc_decrypt(theirs, key, iv) == message)
        total += 1
        same, forward, backward = same + flags[0], forward + flags[1], backward + flags[2]
        if not all(flags) and len(mismatches) < ERROR_LIMIT:
            mismatches.append({"message": hex_bytes(message), "key": H(key), "iv": H(iv)})

    random_iv_ok = 0
    for _ in range(200):
        key, message = rng.randrange(1 << 16), bytes(rng.randrange(256) for _ in range(rng.randrange(0, 33)))
        iv, theirs = peer.cbc_encrypt(message, key)
        random_iv_ok += our_cbc_decrypt(theirs, key, iv) == message

    claimed_cipher = extract(results_text, r"CBC 密文：`([0-9A-F ]+)`")
    claimed_tampered = extract(results_text, r"篡改后明文 bytes：`([0-9A-F ]+)`")
    message, key, iv = b"CBC mode: block chaining test.", 0x4AF5, 0xA1B2
    ours_cipher = our_cbc_encrypt(message, key, iv)
    tampered_cipher = bytearray(ours_cipher)
    tampered_cipher[1] ^= 0x01
    ours_tampered = our_cbc_decrypt(bytes(tampered_cipher), key, iv)
    document = {"cipher": {"peer_document": claimed_cipher, "ours": hex_bytes(ours_cipher), "ok": claimed_cipher == hex_bytes(ours_cipher)},
                "tampered_plaintext": {"peer_document": claimed_tampered, "ours": hex_bytes(ours_tampered), "ok": claimed_tampered == hex_bytes(ours_tampered)}}

    zero_vs_pkcs7 = {"message": hex_bytes(b"AB"), "ours_zero": hex_bytes(modes.blocks_to_bytes(modes.cbc_encrypt_bytes(b"AB", 0x4AF5, 0x1234, "zero"))),
                     "ours_pkcs7": hex_bytes(our_cbc_encrypt(b"AB", 0x4AF5, 0x1234)), "peer": hex_bytes(peer.cbc_encrypt(b"AB", 0x4AF5, 0x1234)[1])}

    interior = {"total": 0, "same_plaintext": 0, "affected_exact": 0, "next_block_xor_mask": 0, "tamper_function_same": 0}
    tail = {"total": 0, "same_outcome": 0, "both_error": 0, "both_plaintext": 0}
    for message in [m for m in messages if len(m) >= 4][:60]:
        key, iv = rng.randrange(1 << 16), rng.randrange(1 << 16)
        _iv, ciphertext = peer.cbc_encrypt(message, key, iv)
        original = peer.cbc_decrypt(ciphertext, key, iv)
        block_count = len(ciphertext) // 2
        for index in range(block_count):
            mask = rng.randrange(1, 1 << 16)
            peer_modified = peer.flip_ciphertext_block_bit(ciphertext, index, mask)
            blocks = modes.bytes_to_blocks(ciphertext)
            blocks[index] ^= mask
            our_modified = modes.blocks_to_bytes(blocks)
            theirs = outcome(lambda: peer.cbc_decrypt(peer_modified, key, iv))
            ours = outcome(lambda: our_cbc_decrypt(our_modified, key, iv))
            if index < block_count - 2:
                interior["total"] += 1
                interior["tamper_function_same"] += peer_modified == our_modified
                interior["same_plaintext"] += theirs == ours and theirs[0] == "ok"
                if theirs[0] == "ok":
                    before_blocks, after_blocks = split_blocks(original), split_blocks(theirs[1])
                    changed = [i for i, (a, b) in enumerate(zip(before_blocks, after_blocks)) if a != b]
                    interior["affected_exact"] += changed == [index, index + 1]
                    interior["next_block_xor_mask"] += int.from_bytes(after_blocks[index + 1], "big") ^ int.from_bytes(before_blocks[index + 1], "big") == mask
            else:
                tail["total"] += 1
                tail["same_outcome"] += theirs == ours
                tail["both_error"] += theirs[0] == "error" and ours[0] == "error"
                tail["both_plaintext"] += theirs[0] == "ok" and ours[0] == "ok"
    return {"total": total, "same_ciphertext": same, "ours_to_peer": forward, "peer_to_ours": backward, "mismatches": mismatches,
            "random_iv": {"total": 200, "ok": random_iv_ok}, "document": document, "zero_vs_pkcs7": zero_vs_pkcs7,
            "tamper_interior": interior, "tamper_tail": tail}


# ------------------------------------------------------------------ 输入校验与错误处理（黑盒观察）
def collect_robustness(peer) -> dict:
    def show(result: tuple) -> str:
        return f"{result[0]} {result[1] if result[0] == 'ok' else result[1]}"

    probes = [
        ("加密：明文 0x10000（超出 16 位）", lambda: peer.encrypt_block(0x10000, 0x4AF5), lambda: core.encrypt_block(0x10000, 0x4AF5)),
        ("加密：密钥 -1", lambda: peer.encrypt_block(0xD728, -1), lambda: core.encrypt_block(0xD728, -1)),
        ("加密：密钥 True（布尔）", lambda: peer.encrypt_block(0xD728, True), lambda: core.encrypt_block(0xD728, True)),
        ("加密：明文为字符串 \"D728\"", lambda: peer.encrypt_block("D728", 0x4AF5), lambda: core.encrypt_block("D728", 0x4AF5)),
        ("ASCII 解密：3 字节（不足整分组）", lambda: peer.decrypt_ascii(b"\x01\x02\x03", 0x4AF5, 3), lambda: modes.ecb_decrypt(modes.bytes_to_blocks(b"\x01\x02\x03"), 0x4AF5)),
        ("ASCII 加密：非 ASCII 文本「信息」", lambda: peer.encrypt_ascii("信息", 0x4AF5)[0].hex(), lambda: modes.blocks_to_bytes(modes.ecb_encrypt(modes.text_to_bytes("信息"), 0x4AF5)).hex()),
        ("CBC 解密：空密文", lambda: peer.cbc_decrypt(b"", 0x4AF5, 0x1234), lambda: our_cbc_decrypt(b"", 0x4AF5, 0x1234)),
        ("CBC：IV 为 0x10000", lambda: peer.cbc_encrypt(b"AB", 0x4AF5, 0x10000), lambda: our_cbc_encrypt(b"AB", 0x4AF5, 0x10000)),
        ("CBC 解密：用错误密钥（合法密文）", lambda: peer.cbc_decrypt(peer.cbc_encrypt(b"hello!", 0x4AF5, 0x1234)[1], 0x4AF6, 0x1234),
         lambda: our_cbc_decrypt(our_cbc_encrypt(b"hello!", 0x4AF5, 0x1234), 0x4AF6, 0x1234)),
        ("中间相遇：0 对明密文", lambda: peer.meet_in_the_middle([]), lambda: multiple.meet_in_the_middle([])),
    ]
    rows = [{"probe": name, "peer": show(outcome(theirs)), "ours": show(outcome(ours))} for name, theirs, ours in probes]
    parse_rows = []
    for text in ("4AF5", "0x4AF5", "  4af5  ", "4AF", "A", "4AF55", "", "GGGG", "4A F5", "0100101011110101"):
        parse_rows.append({"input": text, "peer": show(outcome(lambda: H(peer.parse_hex_block(text)))),
                           "ours": show(outcome(lambda: H(parse_value(text, 16))))})
    return {"probes": rows, "parsing": parse_rows}


# ------------------------------------------------------------------ 对照本身是否有效；复现对方自带的测试
def negative_control(peer_dir: Path, rng: random.Random) -> dict:
    """负对照：在内存里把对方 S 盒的前两项对调（不改文件），同样的对照应当检出大量不一致。"""
    mutated = load_peer(peer_dir, "saes_core_mutated")
    mutated.S_BOX = (mutated.S_BOX[1], mutated.S_BOX[0], *mutated.S_BOX[2:])
    pairs = [(rng.randrange(1 << 16), rng.randrange(1 << 16)) for _ in range(4096)]
    result = sweep(mutated, pairs)
    del sys.modules["saes_core_mutated"]
    return {key: result[key] for key in ("total", "same_ciphertext", "ours_to_peer", "peer_to_ours")}


def reproduce_peer_tests(peer_dir: Path) -> dict:
    """在对方仓库的临时副本里运行它自带的 test_saes.py（它会改写副本里的 results/测试结果.md，原目录不动），再与提交的记录比对。"""
    with tempfile.TemporaryDirectory(prefix="saes_peer_run_") as scratch:
        copy = Path(scratch) / "repo"
        shutil.copytree(peer_dir, copy, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        launcher = ("import runpy, sys; sys.dont_write_bytecode = True; sys.path.insert(0, sys.argv[1]); "
                    "runpy.run_path(sys.argv[1] + '/test_saes.py', run_name='__main__')")
        started = time.perf_counter()
        completed = subprocess.run([sys.executable, "-I", "-c", launcher, str(copy)], capture_output=True, text=True, encoding="utf-8",
                                   cwd=scratch, timeout=300)
        seconds = time.perf_counter() - started
        regenerated = (copy / "results" / "测试结果.md").read_text(encoding="utf-8")
    committed = (peer_dir / "results" / "测试结果.md").read_text(encoding="utf-8")
    changed = [line for line in difflib.unified_diff(committed.splitlines(), regenerated.splitlines(), lineterm="", n=0)
               if line[:1] in "+-" and line[:3] not in ("+++", "---")]
    return {"exit_code": completed.returncode, "seconds": round(seconds, 1), "stderr_tail": completed.stderr[-300:], "different_lines": changed}


# ------------------------------------------------------------------ 主流程
def self_check_summary(data: dict) -> list[str]:
    """汇总所有“应当一致”的对照，返回未通过的项（用于退出码和报告）。"""
    problems = []
    level1, level2, level3, level4, level5 = (data[f"level{n}"] for n in range(1, 6))
    problems += [f"第 1 关向量 {row['plaintext']}/{row['key']}" for row in level1["vectors"] if not row["ok"]]
    sweeps = [level1["edge"], level2["random"], *level2["plaintext_space"].values(), *level2["key_space"].values()]
    problems += [f"第 2 关全空间对照有不一致：{s['mismatches']}" for s in sweeps if not (s["total"] == s["same_ciphertext"] == s["ours_to_peer"] == s["peer_to_ours"])]
    if level2["key_expansion"]["mismatches"]:
        problems.append("密钥扩展不一致")
    problems += [f"对方文档声明与我方不符：{c['claim']}" for c in level2["document_claims"] if c["ours"] != c["expected"]]
    if not all(v["passed"] for v in level2["vector_file"]["verified"].values()):
        problems.append("对方向量文件未通过我方核验")
    if not (level3["total"] == level3["same_ciphertext"] == level3["ours_to_peer"] == level3["peer_to_ours"]):
        problems.append(f"第 3 关 ASCII 不一致：{level3['mismatches']}")
    if not level3["document_claim"]["ok"]:
        problems.append("第 3 关对方文档中的密文与我方不符")
    for name in ("double", "ede2"):
        part = level4[name]
        if not (part["total"] == part["same"] == part["ours_to_peer"] == part["peer_to_ours"]):
            problems.append(f"第 4 关 {name} 不一致")
    if not all(row["ok"] for row in level4["document_double"]):
        problems.append("第 4 关对方文档的双重加密向量与我方不符")
    t48 = level4["triple48"]
    if not (t48["total"] == t48["peer_eee_equals_composed_ours"] == t48["ours_ede3_equals_composed_peer"] == t48["peer_eee_round_trip_ours"]):
        problems.append("第 4 关 48 位三重加密：两端基本分组运算不能互相复现")
    problems += [f"中间相遇 {row['pairs_from']}/{row['pair_count']} 对不一致" for row in level4["mitm"] if not (row["same_set"] and row["contains_true_key"])]
    if not (level5["total"] == level5["same_ciphertext"] == level5["ours_to_peer"] == level5["peer_to_ours"]):
        problems.append(f"第 5 关 CBC 不一致：{level5['mismatches']}")
    if level5["random_iv"]["total"] != level5["random_iv"]["ok"]:
        problems.append("对方随机 IV 的 CBC 密文无法由我方解密")
    problems += [f"第 5 关对方文档记录与我方不符：{name}" for name, item in level5["document"].items() if not item["ok"]]
    interior, tail = level5["tamper_interior"], level5["tamper_tail"]
    if not (interior["total"] == interior["tamper_function_same"] == interior["same_plaintext"] == interior["affected_exact"] == interior["next_block_xor_mask"]):
        problems.append("第 5 关篡改对比（非末尾分组）不一致")
    if tail["total"] != tail["same_outcome"]:
        problems.append("第 5 关篡改对比（末尾两个分组）两端反应不同")
    control = data["negative_control"]
    if control["same_ciphertext"] >= control["total"] // 2:
        problems.append("负对照失效：被改动的对方实现没有被检出")
    if data["peer_own_tests"]["exit_code"] != 0:
        problems.append("对方自带的 test_saes.py 在本机运行失败")
    return problems


def collect(peer_dir: Path) -> dict:
    peer = load_peer(peer_dir)
    rng = random.Random(SEED)
    claims_text = (peer_dir / "外部交叉测试向量.md").read_text(encoding="utf-8")
    results_text = (peer_dir / "results" / "测试结果.md").read_text(encoding="utf-8")
    started = time.perf_counter()
    data = {"meta": {"date": time.strftime("%Y-%m-%d"), "python": f"Python {platform.python_version()}", "system": f"{platform.system()} {platform.release()}",
                     "seed": SEED, "peer_repo": PEER_REPO, "peer_commit": run_git(peer_dir, "rev-parse", "--short", "HEAD"),
                     "peer_commit_date": run_git(peer_dir, "log", "-1", "--format=%cd", "--date=short"),
                     "peer_files": {name: sha256_of(peer_dir / name) for name in ("saes_core.py", "app.py", "test_saes.py")},
                     "our_base_commit": run_git(ROOT, "rev-parse", "--short", "HEAD")}}
    data["level1"] = collect_level1(peer)
    data["level2"] = collect_level2(peer, claims_text, rng)
    data["level3"] = collect_level3(peer, results_text, rng)
    data["level4"] = collect_level4(peer, claims_text, results_text, rng)
    data["level5"] = collect_level5(peer, results_text, rng)
    data["robustness"] = collect_robustness(peer)
    data["negative_control"] = negative_control(peer_dir, rng)
    data["peer_own_tests"] = reproduce_peer_tests(peer_dir)
    data["meta"]["elapsed_seconds"] = round(time.perf_counter() - started)
    data["problems"] = self_check_summary(data)
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="与另一小组的 S-AES 实现做组间互测")
    parser.add_argument("--peer-dir", type=Path, help="对方仓库的克隆目录（含 saes_core.py）")
    parser.add_argument("--render-only", action="store_true", help="只根据已保存的 JSON 重新生成文档")
    arguments = parser.parse_args()
    data_path = ROOT / "reports" / f"cross-test-{PEER_ID}.json"
    if not arguments.render_only:
        if not arguments.peer_dir:
            parser.error("需要 --peer-dir")
        data = collect(arguments.peer_dir.resolve())
        data_path.parent.mkdir(exist_ok=True)
        data_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        (ROOT / "examples" / f"peer-{PEER_ID}-vectors.txt").write_text(data["level2"]["vector_file"]["text"], encoding="utf-8", newline="\n")
        print(f"已保存 {data_path.relative_to(ROOT)}（用时 {data['meta']['elapsed_seconds']} 秒）；未通过项：{data['problems'] or '无'}")
    else:
        data = json.loads(data_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
