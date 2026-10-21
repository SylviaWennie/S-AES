"""简化 AES (S-AES) 参考实现（实现 A：整数运算 + 查表）。

参数与半字节顺序取自教材《密码编码学与网络安全》附录 D。16 位值的最高位是 b0，按图 D.2 分成
N0=b0..b3、N1=b4..b7、N2=b8..b11、N3=b12..b15 四个半字节，状态矩阵按列排列：

    [[S00, S01],     [[N0, N2],
     [S10, S11]]  =   [N1, N3]]

加解密流程用数据（ENCRYPT_PLAN / DECRYPT_PLAN）描述，计算和图解轨迹共用同一份流程。
"""

from functools import lru_cache, reduce

from . import gf16
from .formats import validate_integer

SPEC_ID = "saes-appendix-d-v1"

# 表 D.1(a)、(b)：下标是 4 位输入（左 2 位为行、右 2 位为列），值是 4 位输出
SBOX = (0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7)
INV_SBOX = (0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE)
MIX_MATRIX = ((1, 4), (4, 1))
INV_MIX_MATRIX = ((9, 2), (2, 9))
ROUND_CONSTANTS = (0x80, 0x30)  # RCON(1) = 1000 0000，RCON(2) = 0011 0000

# 每步 = (操作名, 使用的轮密钥序号或 None)
ENCRYPT_PLAN = (("add_key", 0), ("substitute", None), ("shift_rows", None), ("mix_columns", None),
                ("add_key", 1), ("substitute", None), ("shift_rows", None), ("add_key", 2))
DECRYPT_PLAN = (("add_key", 2), ("inv_shift_rows", None), ("inv_substitute", None), ("add_key", 1),
                ("inv_mix_columns", None), ("inv_shift_rows", None), ("inv_substitute", None), ("add_key", 0))

_MULTIPLICATION_TABLE = tuple(tuple(gf16.multiply(a, b) for b in range(16)) for a in range(16))


def split_nibbles(state: int) -> tuple[int, int, int, int]:
    """16 位状态 -> (N0, N1, N2, N3)。"""
    return state >> 12, (state >> 8) & 0xF, (state >> 4) & 0xF, state & 0xF


def join_nibbles(n0: int, n1: int, n2: int, n3: int) -> int:
    return (n0 << 12) | (n1 << 8) | (n2 << 4) | n3


def substitute_nibbles(state: int, box: tuple[int, ...]) -> int:
    """半字节代替：四个半字节分别查 S 盒（NS）或逆 S 盒（INS）。"""
    return join_nibbles(*(box[nibble] for nibble in split_nibbles(state)))


def shift_rows(state: int) -> int:
    """行移位：第二行（N1、N3）循环移一个半字节，即交换两者；自身就是逆变换。"""
    n0, n1, n2, n3 = split_nibbles(state)
    return join_nibbles(n0, n3, n2, n1)


def mix_columns(state: int, matrix: tuple[tuple[int, int], tuple[int, int]]) -> int:
    """列混淆：用 GF(2^4) 上的 2x2 矩阵分别左乘两列 (N0, N1) 和 (N2, N3)。"""
    (a, b), (c, d) = matrix
    n0, n1, n2, n3 = split_nibbles(state)
    mul = _MULTIPLICATION_TABLE
    return join_nibbles(mul[a][n0] ^ mul[b][n1], mul[c][n0] ^ mul[d][n1],
                        mul[a][n2] ^ mul[b][n3], mul[c][n2] ^ mul[d][n3])


def rotate_nibbles(word: int) -> int:
    """RotNib：交换 8 位字的高低半字节。"""
    return ((word & 0xF) << 4) | (word >> 4)


def substitute_word(word: int, box: tuple[int, ...] = SBOX) -> int:
    """SubNib：8 位字的两个半字节分别查 S 盒。"""
    return (box[word >> 4] << 4) | box[word & 0xF]


def g_function(word: int, round_index: int) -> int:
    """g(w) = SubNib(RotNib(w)) ⊕ RCON(i)，i 取 1 或 2。"""
    return substitute_word(rotate_nibbles(word)) ^ ROUND_CONSTANTS[round_index - 1]


@lru_cache(maxsize=1 << 16)
def _expand(key: int) -> tuple[int, ...]:
    w0, w1 = key >> 8, key & 0xFF
    w2 = w0 ^ g_function(w1, 1)
    w3 = w2 ^ w1
    w4 = w2 ^ g_function(w3, 2)
    return w0, w1, w2, w3, w4, w4 ^ w3


def expand_key(key: int) -> tuple[int, ...]:
    """密钥扩展：16 位密钥 -> 6 个 8 位字 w0..w5。"""
    return _expand(validate_integer(key, 16, "密钥"))


def round_keys(key: int) -> tuple[int, int, int]:
    """(K0, K1, K2)：K0=w0w1，K1=w2w3，K2=w4w5。"""
    words = expand_key(key)
    return tuple((words[index] << 8) | words[index + 1] for index in (0, 2, 4))


_OPERATIONS = {
    "add_key": lambda state, key: state ^ key,
    "substitute": lambda state, _key: substitute_nibbles(state, SBOX),
    "inv_substitute": lambda state, _key: substitute_nibbles(state, INV_SBOX),
    "shift_rows": lambda state, _key: shift_rows(state),
    "inv_shift_rows": lambda state, _key: shift_rows(state),
    "mix_columns": lambda state, _key: mix_columns(state, MIX_MATRIX),
    "inv_mix_columns": lambda state, _key: mix_columns(state, INV_MIX_MATRIX),
}


def apply_step(state: int, step: tuple[str, int | None], keys: tuple[int, int, int]) -> int:
    operation, key_index = step
    return _OPERATIONS[operation](state, None if key_index is None else keys[key_index])


def run_plan(plan: tuple, block: int, keys: tuple[int, int, int]) -> int:
    return reduce(lambda state, step: apply_step(state, step, keys), plan, block)


def encrypt_block(plaintext: int, key: int) -> int:
    validate_integer(plaintext, 16, "明文")
    return run_plan(ENCRYPT_PLAN, plaintext, round_keys(key))


def decrypt_block(ciphertext: int, key: int) -> int:
    validate_integer(ciphertext, 16, "密文")
    return run_plan(DECRYPT_PLAN, ciphertext, round_keys(key))


def encrypt_with_keys(plaintext: int, keys: tuple[int, int, int]) -> int:
    """已展开轮密钥时的快速路径，不做输入检查；供穷举类循环使用。"""
    return run_plan(ENCRYPT_PLAN, plaintext, keys)


def decrypt_with_keys(ciphertext: int, keys: tuple[int, int, int]) -> int:
    return run_plan(DECRYPT_PLAN, ciphertext, keys)


def trace_block(block: int, key: int, decrypt: bool = False) -> dict:
    """每一步之后的 16 位状态；图解与命令行 trace 在此基础上扩充。"""
    validate_integer(block, 16, "分组")
    keys = round_keys(key)
    plan = DECRYPT_PLAN if decrypt else ENCRYPT_PLAN
    states = [block]
    for step in plan:
        states.append(apply_step(states[-1], step, keys))
    return {"decrypt": decrypt, "key": key, "round_keys": keys, "words": expand_key(key),
            "plan": plan, "states": states, "result": states[-1]}
