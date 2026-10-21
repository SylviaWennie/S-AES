"""字节串分组（第 3 关）和 CBC 工作模式（第 5 关）。

16 位分组 = 2 字节，高字节在前：字符串 "AB" 对应分组 0x4142。
"""

import secrets
from itertools import accumulate

from .formats import validate_integer
from .implementations import DEFAULT, Implementation

PADDING_SCHEMES = ("zero", "pkcs7", "none")
BLOCK_BYTES = 2


def text_to_bytes(text: str) -> bytes:
    """文本 -> 字节。ASCII 字符的 UTF-8 编码与 ASCII 完全相同，中文等字符按 UTF-8 多字节处理。"""
    if not isinstance(text, str):
        raise ValueError("明文必须是字符串")
    return text.encode("utf-8")


def bytes_to_text(data: bytes) -> str:
    """字节 -> 文本；错误密钥得到的乱码用替换字符显示，不抛异常。"""
    return data.decode("utf-8", errors="replace")


def printable_view(data: bytes) -> str:
    """把任意字节按 Latin-1 字符显示；不可打印字符用 · 代替（密文通常是乱码）。"""
    return "".join(chr(value) if 0x20 <= value < 0x7F else "·" for value in data)


def pad(data: bytes, scheme: str = "zero") -> bytes:
    """补齐到 2 字节的整数倍。zero：必要时补一个 0x00；pkcs7：总是补 1 或 2 个字节；none：要求本来就是偶数。"""
    if scheme == "none":
        if len(data) % BLOCK_BYTES:
            raise ValueError("选择「无填充」时，明文字节数必须是偶数")
        return data
    if scheme == "zero":
        return data + b"\x00" * (len(data) % BLOCK_BYTES)
    if scheme == "pkcs7":
        amount = BLOCK_BYTES - len(data) % BLOCK_BYTES
        return data + bytes([amount]) * amount
    raise ValueError("填充方式只能是 zero、pkcs7 或 none")


def unpad(data: bytes, scheme: str = "zero") -> bytes:
    if scheme == "none":
        return data
    if scheme == "zero":
        return data[:-1] if data.endswith(b"\x00") else data
    if scheme == "pkcs7":
        amount = data[-1] if data else 0
        if not 1 <= amount <= BLOCK_BYTES or data[-amount:] != bytes([amount]) * amount:
            raise ValueError("PKCS#7 填充无效：密钥或密文可能不正确")
        return data[:-amount]
    raise ValueError("填充方式只能是 zero、pkcs7 或 none")


def bytes_to_blocks(data: bytes) -> list[int]:
    if len(data) % BLOCK_BYTES:
        raise ValueError("字节数必须是 2 的整数倍")
    return [(data[index] << 8) | data[index + 1] for index in range(0, len(data), BLOCK_BYTES)]


def blocks_to_bytes(blocks: list[int]) -> bytes:
    return b"".join(validate_integer(block, 16, "分组").to_bytes(2, "big") for block in blocks)


def ecb_encrypt(data: bytes, key: int, padding: str = "zero", cipher: Implementation = DEFAULT) -> list[int]:
    """逐个 2 字节分组独立加密（第 3 关的字符串加密）。"""
    return [cipher.encrypt(block, key) for block in bytes_to_blocks(pad(data, padding))]


def ecb_decrypt(blocks: list[int], key: int, padding: str = "zero", cipher: Implementation = DEFAULT) -> bytes:
    return unpad(blocks_to_bytes([cipher.decrypt(block, key) for block in blocks]), padding)


def random_iv() -> int:
    """随机 16 位初始向量；IV 不需要保密，但加解密双方必须使用同一个值。"""
    return secrets.randbits(16)


def cbc_encrypt_blocks(blocks: list[int], key: int, iv: int, cipher: Implementation = DEFAULT) -> list[int]:
    """C_i = E_K(P_i ⊕ C_{i-1})，C_0 = IV。"""
    validate_integer(iv, 16, "初始向量")
    chain = accumulate(blocks, lambda previous, block: cipher.encrypt(block ^ previous, key), initial=iv)
    return list(chain)[1:]


def cbc_decrypt_blocks(blocks: list[int], key: int, iv: int, cipher: Implementation = DEFAULT) -> list[int]:
    """P_i = D_K(C_i) ⊕ C_{i-1}，C_0 = IV。每个明文分组只依赖相邻的两个密文分组。"""
    validate_integer(iv, 16, "初始向量")
    return [cipher.decrypt(block, key) ^ previous for block, previous in zip(blocks, [iv, *blocks])]


def cbc_encrypt_bytes(data: bytes, key: int, iv: int, padding: str = "zero", cipher: Implementation = DEFAULT) -> list[int]:
    return cbc_encrypt_blocks(bytes_to_blocks(pad(data, padding)), key, iv, cipher)


def cbc_decrypt_bytes(blocks: list[int], key: int, iv: int, padding: str = "zero", cipher: Implementation = DEFAULT) -> bytes:
    return unpad(blocks_to_bytes(cbc_decrypt_blocks(blocks, key, iv, cipher)), padding)
