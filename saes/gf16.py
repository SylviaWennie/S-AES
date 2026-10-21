"""有限域 GF(2^4)：4 位二进制数对应次数不超过 3 的多项式，运算模 x^4 + x + 1。"""

MODULUS = 0b10011  # x^4 + x + 1
_SUPERSCRIPTS = {2: "²", 3: "³", 4: "⁴", 5: "⁵", 6: "⁶"}


def multiply(left: int, right: int) -> int:
    """移位相加乘法：左操作数每左移一位，溢出 x^4 时立即约去模多项式。"""
    product = 0
    while right:
        if right & 1:
            product ^= left
        right >>= 1
        left <<= 1
        if left & 0b10000:
            left ^= MODULUS
    return product


def inverse(value: int) -> int:
    """乘法逆元；0 没有逆元，约定映射为 0（与 S 盒构造一致）。"""
    return 0 if value == 0 else next(c for c in range(1, 16) if multiply(value, c) == 1)


def carryless_product(left: int, right: int) -> int:
    """系数在 GF(2) 上的多项式乘积，不做约简，次数最高为 6。"""
    return _xor_all(left << power for power in range(4) if right >> power & 1)


def reduce_modulo(value: int) -> int:
    """多项式长除法取余：从最高次项开始用模多项式逐项消去。"""
    for power in range(6, 3, -1):
        if value >> power & 1:
            value ^= MODULUS << (power - 4)
    return value


def polynomial_text(value: int) -> str:
    """把二进制数写成多项式，例如 0b1100 -> 'x³+x²'。"""
    names = {0: "1", 1: "x", **{power: "x" + mark for power, mark in _SUPERSCRIPTS.items()}}
    return "+".join(names[power] for power in range(6, -1, -1) if value >> power & 1) or "0"


def describe_product(left: int, right: int) -> dict:
    """给出一次 GF(2^4) 乘法的多项式推导文字，供图解展示（对应教材附件 D.1 的 4·C 示例）。"""
    raw = carryless_product(left, right)
    value = reduce_modulo(raw)
    wrap = lambda number: f"({polynomial_text(number)})" if "+" in polynomial_text(number) else polynomial_text(number)
    text = f"{wrap(left)}·{wrap(right)} = {polynomial_text(raw)}"
    if raw != value:
        text += f" ≡ {polynomial_text(value)} (mod x⁴+x+1)"
    return {"value": value, "text": text}


def _xor_all(values) -> int:
    result = 0
    for value in values:
        result ^= value
    return result
