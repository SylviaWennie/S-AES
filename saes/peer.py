"""组内成员 B 的实现：全部用 0/1 字符串完成。

S 盒按教材表 D.1 的行列版面逐行抄录，列混淆用「乘 x」的位运算（附件 D.2）。
本模块不导入实现 A 的算法或常量，用来和 A 互相核对。
"""

from functools import lru_cache

# 表 D.1：每行 4 个十六进制字符；行号取输入左 2 位，列号取输入右 2 位
_SBOX_ROWS = ("94AB", "D185", "6203", "CEF7")
_INV_SBOX_ROWS = ("A59B", "178F", "6023", "C4DE")
_ROUND_CONSTANTS = ("10000000", "00110000")


def _binary(value: str, width: int, name: str) -> str:
    if not isinstance(value, str) or len(value) != width or set(value) - {"0", "1"}:
        raise ValueError(f"{name}必须恰好是 {width} 位二进制字符（0/1）")
    return value


def _xor(left: str, right: str) -> str:
    return "".join("0" if a == b else "1" for a, b in zip(left, right))


def _lookup(rows: tuple[str, ...], nibble: str) -> str:
    row, column = int(nibble[:2], 2), int(nibble[2:], 2)
    return format(int(rows[row][column], 16), "04b")


def _substitute(bits: str, rows: tuple[str, ...]) -> str:
    return "".join(_lookup(rows, bits[start:start + 4]) for start in range(0, len(bits), 4))


def _shift_rows(state: str) -> str:
    """N0 N1 N2 N3 -> N0 N3 N2 N1（第二行两个半字节互换）。"""
    return state[0:4] + state[12:16] + state[8:12] + state[4:8]


def _times2(nibble: str) -> str:
    """乘 x：b0b1b2b3 -> b1 b2 (b3⊕b0) b0（x^4 ≡ x + 1）。"""
    return nibble[1] + nibble[2] + _xor(nibble[3], nibble[0]) + nibble[0]


def _times4(nibble: str) -> str:
    return _times2(_times2(nibble))


def _times9(nibble: str) -> str:
    """9 = x^3 + 1，所以 9·v = v ⊕ x^3·v。"""
    return _xor(nibble, _times2(_times4(nibble)))


def _mix_columns(state: str, inverse: bool = False) -> str:
    mixed = ""
    for start in (0, 8):  # 两列：(N0, N1) 和 (N2, N3)
        top, bottom = state[start:start + 4], state[start + 4:start + 8]
        if inverse:
            mixed += _xor(_times9(top), _times2(bottom)) + _xor(_times2(top), _times9(bottom))
        else:
            mixed += _xor(top, _times4(bottom)) + _xor(_times4(top), bottom)
    return mixed


def _g(word: str, constant: str) -> str:
    return _xor(_substitute(word[4:] + word[:4], _SBOX_ROWS), constant)


@lru_cache(maxsize=1 << 16)
def _round_keys(key: str) -> tuple[str, str, str]:
    w0, w1 = key[:8], key[8:]
    w2 = _xor(w0, _g(w1, _ROUND_CONSTANTS[0]))
    w3 = _xor(w2, w1)
    w4 = _xor(w2, _g(w3, _ROUND_CONSTANTS[1]))
    w5 = _xor(w4, w3)
    return w0 + w1, w2 + w3, w4 + w5


def transform(block: str, key: str, decrypt: bool = False) -> str:
    """B 端公开接口：16 位串 + 16 位串密钥 -> 16 位串。"""
    _binary(block, 16, "分组")
    _binary(key, 16, "密钥")
    k0, k1, k2 = _round_keys(key)
    if not decrypt:
        state = _xor(block, k0)
        state = _xor(_mix_columns(_shift_rows(_substitute(state, _SBOX_ROWS))), k1)
        return _xor(_shift_rows(_substitute(state, _SBOX_ROWS)), k2)
    state = _xor(block, k2)
    state = _substitute(_shift_rows(state), _INV_SBOX_ROWS)
    state = _mix_columns(_xor(state, k1), inverse=True)
    state = _substitute(_shift_rows(state), _INV_SBOX_ROWS)
    return _xor(state, k0)
