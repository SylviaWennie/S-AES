"""多重加密（第 4 关）：双重加密、三重加密，以及对双重加密的中间相遇攻击。

约定（互测时必须一致）：
  双重  C = E_K2(E_K1(P))，P = D_K1(D_K2(C))，密钥 32 位 = K1 ‖ K2（K1 在高位）。
  三重  EDE：32 位密钥 K1‖K2 用 C = E_K1(D_K2(E_K1(P)))；48 位密钥 K1‖K2‖K3 用 C = E_K3(D_K2(E_K1(P)))。
"""

from time import perf_counter_ns

from . import core
from .formats import validate_integer
from .implementations import DEFAULT, Implementation

TRIPLE_MODES = {"ede2": 32, "ede3": 48}  # 模式 -> 密钥位数
KEY_SPACE = 1 << 16


def split_key(key: int, parts: int) -> list[int]:
    """把 16*parts 位密钥拆成 parts 个 16 位子密钥，K1 在最高位。"""
    validate_integer(key, 16 * parts, f"{16 * parts} 位密钥")
    return [(key >> (16 * (parts - 1 - index))) & 0xFFFF for index in range(parts)]


def double_encrypt(block: int, key: int, cipher: Implementation = DEFAULT) -> int:
    k1, k2 = split_key(key, 2)
    return cipher.encrypt(cipher.encrypt(block, k1), k2)


def double_decrypt(block: int, key: int, cipher: Implementation = DEFAULT) -> int:
    k1, k2 = split_key(key, 2)
    return cipher.decrypt(cipher.decrypt(block, k2), k1)


def triple_keys(key: int, mode: str) -> list[int]:
    """EDE2 把 K1 复用为第三把密钥，EDE3 使用三把独立密钥。"""
    if mode not in TRIPLE_MODES:
        raise ValueError("三重加密模式只能是 ede2（32 位密钥）或 ede3（48 位密钥）")
    parts = split_key(key, TRIPLE_MODES[mode] // 16)
    return [parts[0], parts[1], parts[0] if mode == "ede2" else parts[2]]


def triple_encrypt(block: int, key: int, mode: str, cipher: Implementation = DEFAULT) -> int:
    k1, k2, k3 = triple_keys(key, mode)
    return cipher.encrypt(cipher.decrypt(cipher.encrypt(block, k1), k2), k3)


def triple_decrypt(block: int, key: int, mode: str, cipher: Implementation = DEFAULT) -> int:
    k1, k2, k3 = triple_keys(key, mode)
    return cipher.decrypt(cipher.encrypt(cipher.decrypt(block, k3), k2), k1)


def meet_in_the_middle(pairs: list[tuple[int, int]]) -> dict:
    """已知若干 (明文, 密文) 对，求出所有满足 E_K2(E_K1(P)) = C 的 (K1, K2)。

    先用第一对：枚举全部 K1 得到中间值 E_K1(P) 的查找表，再枚举全部 K2 计算 D_K2(C)，
    表中命中的 K1 与该 K2 组成候选；其余明密文对只需逐个验证候选。
    总共约 2·2^16 次分组运算，而不是穷举 2^32 对密钥。
    """
    if not 1 <= len(pairs) <= 16:
        raise ValueError("需要 1–16 对明密文")
    for plaintext, ciphertext in pairs:
        validate_integer(plaintext, 16, "明文")
        validate_integer(ciphertext, 16, "密文")
    started = perf_counter_ns()
    first_plaintext, first_ciphertext = pairs[0]
    middle_table: dict[int, list[int]] = {}
    for k1 in range(KEY_SPACE):
        middle_table.setdefault(core.encrypt_with_keys(first_plaintext, core.round_keys(k1)), []).append(k1)
    table_ns = perf_counter_ns() - started
    candidates = [(k1 << 16) | k2 for k2 in range(KEY_SPACE)
                  for k1 in middle_table.get(core.decrypt_with_keys(first_ciphertext, core.round_keys(k2)), ())]
    counts = [len(candidates)]
    operations = 2 * KEY_SPACE  # 建表 2^16 次加密 + 匹配 2^16 次解密
    for plaintext, ciphertext in pairs[1:]:
        operations += 2 * len(candidates)  # 每个候选验证一对需要 2 次分组加密
        candidates = [key for key in candidates if double_encrypt(plaintext, key) == ciphertext]
        counts.append(len(candidates))
    elapsed_ns = perf_counter_ns() - started
    return {"candidates": candidates, "counts": counts, "block_operations": operations,
            "table_entries": KEY_SPACE, "table_ms": table_ns / 1e6, "elapsed_ms": elapsed_ns / 1e6}


def estimate_exhaustive_seconds(sample_operations: int = 20000) -> dict:
    """按本机单次分组加密的实测耗时，外推穷举 2^32 把双重密钥所需时间（估算，不是实测）。"""
    keys = core.round_keys(0x2D55)
    started = perf_counter_ns()
    for index in range(sample_operations):
        core.encrypt_with_keys(index & 0xFFFF, keys)
    per_operation_ns = (perf_counter_ns() - started) / sample_operations
    # 最优的穷举：外层枚举 K1 并复用中间值 E_K1(P)，内层每个 K2 只需 1 次加密，共约 2^32 次
    exhaustive_operations = (1 << 32) + (1 << 16)
    return {"per_operation_us": per_operation_ns / 1e3, "exhaustive_operations": exhaustive_operations,
            "estimated_seconds": per_operation_ns * exhaustive_operations / 1e9}
