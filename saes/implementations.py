"""组内三种独立实现的统一入口：接口都是 (16 位整数, 16 位整数密钥) -> 16 位整数。"""

from dataclasses import dataclass
from typing import Callable

from . import core, matrix, peer
from .formats import bits


@dataclass(frozen=True)
class Implementation:
    key: str
    name: str
    style: str
    encrypt: Callable[[int, int], int]
    decrypt: Callable[[int, int], int]


def _through_strings(decrypt: bool) -> Callable[[int, int], int]:
    """把整数接口适配到 B 端的 0/1 字符串接口。"""
    return lambda block, key: int(peer.transform(bits(block), bits(key), decrypt), 2)


IMPLEMENTATIONS = {
    "A": Implementation("A", "实现 A · 整数运算 + 查表",
                        "整数位运算；S 盒、GF(2⁴) 乘法用查表，加解密流程由数据描述（saes.core）",
                        core.encrypt_block, core.decrypt_block),
    "B": Implementation("B", "实现 B · 0/1 字符串",
                        "全程 0/1 字符串，列混淆用「乘 x」的位运算（saes.peer）",
                        _through_strings(False), _through_strings(True)),
    "C": Implementation("C", "实现 C · GF(2⁴) 多项式矩阵",
                        "S 盒由「求逆 + 仿射变换」构造，解密用教材 D.5 的等价逆算法（saes.matrix）",
                        matrix.encrypt, matrix.decrypt),
}

DEFAULT = IMPLEMENTATIONS["A"]


def get_implementation(key: str) -> Implementation:
    if key not in IMPLEMENTATIONS:
        raise ValueError("实现编号只能是 A、B 或 C")
    return IMPLEMENTATIONS[key]
