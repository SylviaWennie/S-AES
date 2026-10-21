"""组内成员 C 的实现：状态是 GF(2^4) 元素组成的 2x2 矩阵。

S 盒由「GF(2^4) 求逆 + 仿射变换」构造而不是抄表，轮常数由 RC[i] = x^(i+2) 算出，
解密采用教材 D.5 的等价逆算法 A_K0∘INS∘ISR∘A_IMC(K1)∘IMC∘ISR∘INS∘A_K2。
本模块不导入实现 A 的算法或常量。
"""

from functools import lru_cache

_COEFFICIENT_POWERS = (3, 2, 1, 0)


def _to_polynomial(value: int) -> list[int]:
    """4 位数 a0a1a2a3 -> 系数列表 [a0, a1, a2, a3]（x^3 到 x^0）。"""
    return [(value >> power) & 1 for power in _COEFFICIENT_POWERS]


def _from_polynomial(coefficients: list[int]) -> int:
    return sum(bit << power for bit, power in zip(coefficients, _COEFFICIENT_POWERS))


def _reduce(coefficients: list[int]) -> list[int]:
    """多项式长除法：最高次项 x^n 用 x^4 = x + 1 代换，直到只剩 4 项。"""
    remaining = list(coefficients)
    while len(remaining) > 4:
        leading = remaining.pop(0)
        if leading:
            remaining[2] ^= 1  # x^(n-4)
            remaining[3] ^= 1  # x^(n-5)
    return remaining


def _multiply(left: int, right: int) -> int:
    product = [0] * 7
    for i, a in enumerate(_to_polynomial(left)):
        for j, b in enumerate(_to_polynomial(right)):
            product[i + j] ^= a & b
    return _from_polynomial(_reduce(product))


def _inverse(value: int) -> int:
    return 0 if value == 0 else next(c for c in range(1, 16) if _multiply(value, c) == 1)


_AFFINE_ROWS = ((1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, 0), (0, 1, 1, 1))
_AFFINE_CONSTANT = (1, 0, 0, 1)


def _affine(value: int) -> int:
    bits = _to_polynomial(value)
    mixed = [(sum(a * b for a, b in zip(row, bits)) % 2) ^ c for row, c in zip(_AFFINE_ROWS, _AFFINE_CONSTANT)]
    return _from_polynomial(mixed)


_SBOX = tuple(_affine(_inverse(value)) for value in range(16))
_INV_SBOX = tuple(_SBOX.index(value) for value in range(16))


def _round_constant(index: int) -> int:
    """RC[i] = x^(i+2) mod (x^4 + x + 1)，放在字节的左半字节。"""
    return _from_polynomial(_reduce([1] + [0] * (index + 2))) << 4


def _to_matrix(value: int) -> list[list[int]]:
    """按列排列：N0 N1 N2 N3 -> [[N0, N2], [N1, N3]]。"""
    return [[(value >> 12) & 15, (value >> 4) & 15], [(value >> 8) & 15, value & 15]]


def _from_matrix(matrix: list[list[int]]) -> int:
    return (matrix[0][0] << 12) | (matrix[1][0] << 8) | (matrix[0][1] << 4) | matrix[1][1]


def _multiply_matrices(left: list[list[int]], right: list[list[int]]) -> list[list[int]]:
    return [[_multiply(left[row][0], right[0][column]) ^ _multiply(left[row][1], right[1][column])
             for column in range(2)] for row in range(2)]


def _add_matrices(left: list[list[int]], right: list[list[int]]) -> list[list[int]]:
    return [[a ^ b for a, b in zip(left_row, right_row)] for left_row, right_row in zip(left, right)]


def _substitute(matrix: list[list[int]], box: tuple[int, ...]) -> list[list[int]]:
    return [[box[cell] for cell in row] for row in matrix]


def _shift_rows(matrix: list[list[int]]) -> list[list[int]]:
    return [matrix[0], matrix[1][::-1]]


_MIX = [[1, 4], [4, 1]]
_INV_MIX = [[9, 2], [2, 9]]


@lru_cache(maxsize=1 << 16)
def _round_key_matrices(key: int) -> tuple[list[list[int]], ...]:
    def g(word: int, index: int) -> int:
        rotated = ((word & 15) << 4) | (word >> 4)
        return ((_SBOX[rotated >> 4] << 4) | _SBOX[rotated & 15]) ^ _round_constant(index)

    w0, w1 = key >> 8, key & 255
    w2 = w0 ^ g(w1, 1)
    w3 = w2 ^ w1
    w4 = w2 ^ g(w3, 2)
    w5 = w4 ^ w3
    return tuple(_to_matrix((high << 8) | low) for high, low in ((w0, w1), (w2, w3), (w4, w5)))


def _check(value: int, name: str) -> int:
    if type(value) is not int or not 0 <= value < 65536:
        raise ValueError(f"{name}必须是 0 到 65535 的整数")
    return value


def encrypt(block: int, key: int) -> int:
    k0, k1, k2 = _round_key_matrices(_check(key, "密钥"))
    state = _add_matrices(_to_matrix(_check(block, "分组")), k0)
    state = _add_matrices(_multiply_matrices(_MIX, _shift_rows(_substitute(state, _SBOX))), k1)
    return _from_matrix(_add_matrices(_shift_rows(_substitute(state, _SBOX)), k2))


def decrypt(block: int, key: int) -> int:
    """等价逆算法：先对 K1 做逆列混淆，使解密流程与加密流程同构。"""
    k0, k1, k2 = _round_key_matrices(_check(key, "密钥"))
    state = _add_matrices(_to_matrix(_check(block, "分组")), k2)
    state = _substitute(_shift_rows(state), _INV_SBOX)
    state = _add_matrices(_multiply_matrices(_INV_MIX, state), _multiply_matrices(_INV_MIX, k1))
    state = _substitute(_shift_rows(state), _INV_SBOX)
    return _from_matrix(_add_matrices(state, k0))
