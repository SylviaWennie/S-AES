"""可由另一组程序读取的算法约定与测试向量（交叉测试，第 2 关）。

交换文件是 JSON；也支持每行「明文 密钥 密文」的纯文本，三列各自写成 16 位二进制或 4 位十六进制。
"""

import re

from .core import SPEC_ID
from .formats import bits, hex_text, parse_value
from .implementations import DEFAULT, Implementation

SCHEMA = "saes-cross-test-v1"
MAX_VECTORS = 4096

CONVENTIONS = {
    "block_and_key": "16 位；b0 是最高位，十六进制写法与二进制一致（0x6F6B = 0110 1111 0110 1011）",
    "state_layout": "按列排列：N0=b0..b3, N1=b4..b7, N2=b8..b11, N3=b12..b15；状态矩阵 [[N0,N2],[N1,N3]]",
    "encrypt_rounds": "AK0 | NS SR MC AK1 | NS SR AK2（第 2 轮没有列混淆）",
    "sbox": "9 4 A B D 1 8 5 6 2 0 3 C E F 7（输入左 2 位为行、右 2 位为列，表 D.1(a)）",
    "mix_columns": "[[1,4],[4,1]]，GF(2^4) 模 x^4+x+1；逆为 [[9,2],[2,9]]",
    "key_expansion": "w0w1=密钥；w2=w0⊕RCON(1)⊕SubNib(RotNib(w1))，w3=w2⊕w1，w4=w2⊕RCON(2)⊕SubNib(RotNib(w3))，w5=w4⊕w3；RCON(1)=80，RCON(2)=30",
    "round_keys": "K0=w0w1，K1=w2w3，K2=w4w5",
}


def _vector(plaintext: int, key: int, cipher: Implementation) -> dict:
    ciphertext = cipher.encrypt(plaintext, key)
    return {"plaintext": bits(plaintext), "key": bits(key), "ciphertext": bits(ciphertext),
            "plaintext_hex": hex_text(plaintext), "key_hex": hex_text(key), "ciphertext_hex": hex_text(ciphertext)}


def make_exchange(key: int, plaintexts: list[int], cipher: Implementation = DEFAULT) -> dict:
    if not 1 <= len(plaintexts) <= MAX_VECTORS:
        raise ValueError(f"交换文件需要 1–{MAX_VECTORS} 条向量")
    return {"schema": SCHEMA, "spec_id": SPEC_ID, "conventions": CONVENTIONS,
            "purpose": "public educational test vectors; keys intentionally included",
            "vectors": [_vector(plaintext, key, cipher) for plaintext in plaintexts]}


def parse_vector_lines(text: str) -> list[tuple[int, int, int]]:
    """逐行解析「明文 密钥 密文」；空行和 # 之后的注释忽略，分隔符可以是空白或逗号。"""
    vectors = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [part for part in re.split(r"[\s,;]+", line) if part]
        if len(parts) != 3:
            raise ValueError(f"第 {number} 行需要三列：明文 密钥 密文")
        vectors.append(tuple(parse_value(part, 16, name) for part, name in zip(parts, ("明文", "密钥", "密文"))))
    if not 1 <= len(vectors) <= MAX_VECTORS:
        raise ValueError(f"需要 1–{MAX_VECTORS} 条向量")
    return vectors


def vectors_from_document(document: dict) -> list[tuple[int, int, int]]:
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ValueError("不支持的交换文件格式")
    if document.get("spec_id") != SPEC_ID:
        raise ValueError("算法约定不同：请先核对 S 盒、列混淆矩阵、密钥扩展常量和半字节排列顺序")
    items = document.get("vectors")
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_VECTORS:
        raise ValueError(f"交换文件需要 1–{MAX_VECTORS} 条向量")
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("向量必须是对象")
    return [(parse_value(item.get("plaintext"), 16, "明文"), parse_value(item.get("key"), 16, "密钥"),
             parse_value(item.get("ciphertext"), 16, "密文")) for item in items]


def verify_vectors(vectors: list[tuple[int, int, int]], cipher: Implementation = DEFAULT) -> dict:
    """逐条核对：对方给出的密文是否等于本机加密结果，对方的明文是否等于本机解密结果。"""
    rows = []
    for index, (plaintext, key, ciphertext) in enumerate(vectors, 1):
        actual_ciphertext = cipher.encrypt(plaintext, key)
        actual_plaintext = cipher.decrypt(ciphertext, key)
        rows.append({"index": index, "plaintext": bits(plaintext), "key": bits(key), "ciphertext": bits(ciphertext),
                     "encrypt_ok": actual_ciphertext == ciphertext, "decrypt_ok": actual_plaintext == plaintext,
                     "actual_ciphertext": bits(actual_ciphertext), "actual_plaintext": bits(actual_plaintext)})
    return {"passed": all(row["encrypt_ok"] and row["decrypt_ok"] for row in rows), "total": len(rows),
            "encrypt_passed": sum(row["encrypt_ok"] for row in rows),
            "decrypt_passed": sum(row["decrypt_ok"] for row in rows), "results": rows}


def verify_exchange(document: dict, cipher: Implementation = DEFAULT) -> dict:
    return verify_vectors(vectors_from_document(document), cipher)
