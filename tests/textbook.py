"""教材《密码编码学与网络安全》附录 D 中的表格与示例，按原书抄录。

仅用于测试，生产代码不引用本文件，因此能独立检查 saes 中的常量与算法。
"""

# 表 D.2(b)：模 x^4+x+1 的 GF(2^4) 乘法表；MULTIPLICATION[a] 的第 b 个字符 = a·b
MULTIPLICATION = {
    0x0: "0000000000000000",
    0x1: "0123456789ABCDEF",
    0x2: "02468ACE3175B9FD",
    0x3: "0365CFA9B8DE7412",
    0x4: "048C37BF62EA51D9",
    0x5: "05AF72D8EB419C36",
    0x6: "06CABD71539FE824",
    0x7: "07E9F816DA3425CB",
    0x8: "083B6E5DC4F7A291",
    0x9: "09182B3A4D5C6F7E",
    0xA: "0A7DE493F5821B6C",
    0xB: "0B5EA1F47C29D683",
    0xC: "0CB759E2A61DF348",
    0xD: "0D941C852FB63EA7",
    0xE: "0EF1D32C97684AB5",
    0xF: "0FD2964B1EC3875A",
}

# 表 D.1(a)、(b)：每行依次是列 00、01、10、11 的输出，行号是输入的高 2 位
SBOX_ROWS = ("94AB", "D185", "6203", "CEF7")
INV_SBOX_ROWS = ("A59B", "178F", "6023", "C4DE")

# D.2.1–D.2.4 的例子；状态矩阵写成 [[S00, S01], [S10, S11]]
ADD_ROUND_KEY_EXAMPLE = ([[0xA, 0x4], [0x7, 0x9]], [[0x2, 0x5], [0xD, 0x5]], [[0x8, 0x1], [0xA, 0xC]])
SUBSTITUTION_EXAMPLE = ([[0x8, 0x1], [0xA, 0xC]], [[0x6, 0x4], [0x0, 0xC]])
SHIFT_ROWS_EXAMPLE = ([[0x6, 0x4], [0x0, 0xC]], [[0x6, 0x4], [0xC, 0x0]])
MIX_COLUMNS_EXAMPLE = ([[0x6, 0x4], [0xC, 0x0]], [[0x3, 0x4], [0x7, 0x3]])

# D.3 的密钥扩展例子：密钥 2D55，w2..w5 的二进制
KEY_EXPANSION_KEY = 0x2D55
KEY_EXPANSION_WORDS = ("10111100", "11101001", "10100011", "01001010")
SUBNIB_EXAMPLES = (("01010101", "00010001"), ("10011110", "00101111"))


def matrix_to_state(matrix: list[list[int]]) -> int:
    """按图 D.2 的列优先顺序把 2x2 矩阵拼成 16 位值：N0=S00, N1=S10, N2=S01, N3=S11。"""
    return (matrix[0][0] << 12) | (matrix[1][0] << 8) | (matrix[0][1] << 4) | matrix[1][1]


def multiplication(a: int, b: int) -> int:
    return int(MULTIPLICATION[a][b], 16)


def mix_columns_by_bit_formulas(state: int) -> int:
    """附件 D.2 给出的列混淆位运算公式（b0 是最高位）。"""
    b = [(state >> (15 - index)) & 1 for index in range(16)]
    nibbles = (
        (b[0] ^ b[6], b[1] ^ b[4] ^ b[7], b[2] ^ b[4] ^ b[5], b[3] ^ b[5]),            # s'0,0
        (b[2] ^ b[4], b[0] ^ b[3] ^ b[5], b[0] ^ b[1] ^ b[6], b[1] ^ b[7]),            # s'1,0
        (b[8] ^ b[14], b[9] ^ b[12] ^ b[15], b[10] ^ b[12] ^ b[13], b[11] ^ b[13]),    # s'0,1
        (b[10] ^ b[12], b[8] ^ b[11] ^ b[13], b[8] ^ b[9] ^ b[14], b[9] ^ b[15]),      # s'1,1
    )
    return sum(bit << (15 - 4 * position - offset) for position, nibble in enumerate(nibbles)
               for offset, bit in enumerate(nibble))
