"""输入解析与输出格式化：16 位数据、密钥等既可写成二进制串，也可写成十六进制。"""

_BINARY = frozenset("01")
_HEX = frozenset("0123456789abcdefABCDEF")


def validate_integer(value: int, width: int, name: str) -> int:
    """要求 value 是 0 到 2^width-1 的整数；布尔值不算整数输入。"""
    if type(value) is not int or not 0 <= value < (1 << width):
        raise ValueError(f"{name}必须是 0 到 {(1 << width) - 1} 的整数")
    return value


def parse_bits(value: str, width: int, name: str = "输入") -> int:
    """严格宽度的 0/1 字符串 -> 整数；允许用空白分隔，方便按半字节书写。"""
    compact = "".join(value.split()) if isinstance(value, str) else ""
    if len(compact) != width or set(compact) - _BINARY:
        raise ValueError(f"{name}必须恰好是 {width} 位二进制字符（0/1）")
    return int(compact, 2)


def parse_hex(value: str, width: int, name: str = "输入") -> int:
    """width 位二进制数对应的十六进制字符串（可带 0x 前缀）-> 整数。"""
    compact = "".join(value.split()) if isinstance(value, str) else ""
    compact = compact[2:] if compact[:2] in ("0x", "0X") else compact
    if len(compact) != width // 4 or set(compact) - _HEX:
        raise ValueError(f"{name}必须恰好是 {width // 4} 位十六进制字符")
    return int(compact, 16)


def parse_value(value: str, width: int, name: str = "输入") -> int:
    """接受 width 位二进制或 width/4 位十六进制；两种长度不会混淆。"""
    compact = "".join(value.split()) if isinstance(value, str) else ""
    if len(compact) == width:
        return parse_bits(compact, width, name)
    if len(compact.removeprefix("0x").removeprefix("0X")) == width // 4:
        return parse_hex(compact, width, name)
    raise ValueError(f"{name}必须是 {width} 位二进制或 {width // 4} 位十六进制")


def bits(value: int, width: int = 16) -> str:
    return format(value, f"0{width}b")


def grouped_bits(value: int, width: int = 16) -> str:
    """每 4 位插入一个空格，例如 0110 1111 0110 1011。"""
    text = bits(value, width)
    return " ".join(text[index:index + 4] for index in range(0, width, 4))


def hex_text(value: int, width: int = 16) -> str:
    return format(value, f"0{width // 4}X")


def describe(value: int, width: int = 16) -> dict:
    """同时给出整数、二进制、分组二进制和十六进制，供接口返回。"""
    return {"value": value, "bits": bits(value, width), "grouped": grouped_bits(value, width),
            "hex": hex_text(value, width)}
