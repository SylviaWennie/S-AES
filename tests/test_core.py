"""第 1 关：算法本体。对照教材附录 D 的表格与示例，并与另外两种独立实现逐项比较。

设置环境变量 SAES_FAST=1 可跳过耗时的全空间对照。
"""

import os
import random
import unittest

from saes import core, formats, gf16, matrix, peer
from saes.implementations import IMPLEMENTATIONS

from . import textbook

SKIP_HEAVY = unittest.skipIf(os.environ.get("SAES_FAST"), "SAES_FAST=1：跳过全空间对照")
KNOWN_PLAINTEXT, KNOWN_KEY, KNOWN_CIPHERTEXT = 0x6F6B, 0xA73B, 0x0738


class GaloisFieldTests(unittest.TestCase):
    def test_multiplication_table_matches_textbook(self):
        for a in range(16):
            for b in range(16):
                self.assertEqual(gf16.multiply(a, b), textbook.multiplication(a, b), (a, b))

    def test_shift_and_add_agrees_with_polynomial_division(self):
        for a in range(16):
            for b in range(16):
                self.assertEqual(gf16.multiply(a, b), gf16.reduce_modulo(gf16.carryless_product(a, b)))

    def test_inverse(self):
        self.assertEqual(gf16.inverse(0), 0)
        for value in range(1, 16):
            self.assertEqual(gf16.multiply(value, gf16.inverse(value)), 1)

    def test_worked_example_from_appendix(self):
        result = gf16.describe_product(4, 0xC)  # 附件 D.1：4·C = x⁵+x⁴ mod (x⁴+x+1) = x²+1 = 5
        self.assertEqual(result["value"], 5)
        self.assertIn("x⁵+x⁴", result["text"])
        self.assertIn("x²+1", result["text"])


class TransformationTests(unittest.TestCase):
    def test_sbox_tables_match_textbook_layout(self):
        for row, (forward, backward) in enumerate(zip(textbook.SBOX_ROWS, textbook.INV_SBOX_ROWS)):
            for column in range(4):
                self.assertEqual(core.SBOX[row * 4 + column], int(forward[column], 16))
                self.assertEqual(core.INV_SBOX[row * 4 + column], int(backward[column], 16))

    def test_sbox_pair_is_consistent_and_bijective(self):
        self.assertEqual(sorted(core.SBOX), list(range(16)))
        for value in range(16):
            self.assertEqual(core.INV_SBOX[core.SBOX[value]], value)

    def test_sbox_equals_algebraic_construction(self):
        self.assertEqual(core.SBOX, matrix._SBOX)  # 实现 C 用「求逆 + 仿射变换」构造
        self.assertEqual(core.INV_SBOX, matrix._INV_SBOX)

    def test_appendix_examples(self):
        state, key, expected = (textbook.matrix_to_state(item) for item in textbook.ADD_ROUND_KEY_EXAMPLE)
        self.assertEqual(state ^ key, expected)
        before, after = (textbook.matrix_to_state(item) for item in textbook.SUBSTITUTION_EXAMPLE)
        self.assertEqual(core.substitute_nibbles(before, core.SBOX), after)
        self.assertEqual(core.substitute_nibbles(after, core.INV_SBOX), before)
        before, after = (textbook.matrix_to_state(item) for item in textbook.SHIFT_ROWS_EXAMPLE)
        self.assertEqual(core.shift_rows(before), after)
        self.assertEqual(core.shift_rows(after), before)
        before, after = (textbook.matrix_to_state(item) for item in textbook.MIX_COLUMNS_EXAMPLE)
        self.assertEqual(core.mix_columns(before, core.MIX_MATRIX), after)
        self.assertEqual(core.mix_columns(after, core.INV_MIX_MATRIX), before)

    def test_substitution_example_in_text(self):
        # 正文：十六进制值 A 代表 S 盒第 2 行、第 2 列的值 0，因此 A 映射为 0
        self.assertEqual(core.SBOX[0xA], 0x0)
        self.assertEqual((0xA >> 2, 0xA & 3), (2, 2))

    def test_inverse_mix_columns_proof_in_text(self):
        # 正文：9 + (2·4) = 9 + 8 = 1，以及 (9·4) + 2 = 2 + 2 = 0
        self.assertEqual(9 ^ gf16.multiply(2, 4), 1)
        self.assertEqual(gf16.multiply(9, 4) ^ 2, 0)

    def test_mix_columns_matches_appendix_bit_formulas(self):
        for state in range(1 << 16):
            self.assertEqual(core.mix_columns(state, core.MIX_MATRIX), textbook.mix_columns_by_bit_formulas(state))

    def test_inverse_functions_over_all_states(self):
        for state in range(1 << 16):
            mixed = core.mix_columns(state, core.MIX_MATRIX)
            self.assertEqual(core.mix_columns(mixed, core.INV_MIX_MATRIX), state)
            substituted = core.substitute_nibbles(state, core.SBOX)
            self.assertEqual(core.substitute_nibbles(substituted, core.INV_SBOX), state)
            self.assertEqual(core.shift_rows(core.shift_rows(state)), state)

    def test_substitution_and_shift_rows_commute(self):
        # D.5：INS(ISR(N)) = ISR(INS(N))
        for state in range(1 << 16):
            self.assertEqual(core.substitute_nibbles(core.shift_rows(state), core.INV_SBOX),
                             core.shift_rows(core.substitute_nibbles(state, core.INV_SBOX)))

    def test_inverse_mix_columns_distributes_over_round_key(self):
        # D.5：IMC(A_K(N)) = A_IMC(K)(IMC(N))，据此可得到等价逆算法
        rng = random.Random(5)
        for _ in range(20000):
            state, key = rng.getrandbits(16), rng.getrandbits(16)
            self.assertEqual(core.mix_columns(state ^ key, core.INV_MIX_MATRIX),
                             core.mix_columns(state, core.INV_MIX_MATRIX) ^ core.mix_columns(key, core.INV_MIX_MATRIX))


class KeyExpansionTests(unittest.TestCase):
    def test_appendix_example(self):
        words = core.expand_key(textbook.KEY_EXPANSION_KEY)
        self.assertEqual(words[:2], (0x2D, 0x55))
        self.assertEqual(tuple(format(word, "08b") for word in words[2:]), textbook.KEY_EXPANSION_WORDS)

    def test_subnib_examples(self):
        for before, after in textbook.SUBNIB_EXAMPLES:
            self.assertEqual(format(core.substitute_word(int(before, 2)), "08b"), after)

    def test_round_constants(self):
        self.assertEqual(core.ROUND_CONSTANTS, (0b10000000, 0b00110000))
        self.assertEqual(matrix._round_constant(1), core.ROUND_CONSTANTS[0])  # RC[i] = x^(i+2)
        self.assertEqual(matrix._round_constant(2), core.ROUND_CONSTANTS[1])

    def test_round_keys_layout(self):
        k0, k1, k2 = core.round_keys(textbook.KEY_EXPANSION_KEY)
        self.assertEqual((k0, k1, k2), (0x2D55, 0xBCE9, 0xA34A))

    def test_expand_key_rejects_invalid_values(self):
        for value in (-1, 65536, True, "2D55", 3.0, None):
            with self.assertRaises(ValueError):
                core.expand_key(value)


class BlockCipherTests(unittest.TestCase):
    def test_known_vector_with_intermediate_states(self):
        trace = core.trace_block(KNOWN_PLAINTEXT, KNOWN_KEY)
        self.assertEqual([format(state, "04X") for state in trace["states"]],
                         ["6F6B", "C850", "C619", "C916", "ECA2", "F085", "7961", "7169", "0738"])
        self.assertEqual(core.encrypt_block(KNOWN_PLAINTEXT, KNOWN_KEY), KNOWN_CIPHERTEXT)
        self.assertEqual(core.decrypt_block(KNOWN_CIPHERTEXT, KNOWN_KEY), KNOWN_PLAINTEXT)
        self.assertEqual([format(key, "04X") for key in core.round_keys(KNOWN_KEY)], ["A73B", "1C27", "7651"])

    def test_decryption_trace_mirrors_encryption(self):
        encrypt = core.trace_block(KNOWN_PLAINTEXT, KNOWN_KEY)["states"]
        decrypt = core.trace_block(KNOWN_CIPHERTEXT, KNOWN_KEY, decrypt=True)["states"]
        self.assertEqual(decrypt, encrypt[::-1])

    def test_encryption_matches_hand_written_composition(self):
        rng = random.Random(11)
        for _ in range(500):
            plaintext, key = rng.getrandbits(16), rng.getrandbits(16)
            k0, k1, k2 = core.round_keys(key)
            state = core.shift_rows(core.substitute_nibbles(plaintext ^ k0, core.SBOX))
            state = core.mix_columns(state, core.MIX_MATRIX) ^ k1
            state = core.shift_rows(core.substitute_nibbles(state, core.SBOX)) ^ k2
            self.assertEqual(core.encrypt_block(plaintext, key), state)

    def test_decrypt_inverts_encrypt(self):
        rng = random.Random(12)
        for _ in range(5000):
            plaintext, key = rng.getrandbits(16), rng.getrandbits(16)
            self.assertEqual(core.decrypt_block(core.encrypt_block(plaintext, key), key), plaintext)
            self.assertEqual(core.encrypt_block(core.decrypt_block(plaintext, key), key), plaintext)

    def test_each_key_gives_a_permutation(self):
        for key in (0x0000, 0xFFFF, KNOWN_KEY, 0x2D55):
            self.assertEqual(len({core.encrypt_block(plaintext, key) for plaintext in range(1 << 16)}), 1 << 16)

    def test_wrong_key_does_not_decrypt(self):
        ciphertext = core.encrypt_block(KNOWN_PLAINTEXT, KNOWN_KEY)
        self.assertNotEqual(core.decrypt_block(ciphertext, KNOWN_KEY ^ 0x0001), KNOWN_PLAINTEXT)

    def test_rejects_invalid_input(self):
        for bad in (-1, 65536, True, False, "6F6B", 1.5, None):
            with self.assertRaises(ValueError):
                core.encrypt_block(bad, 0)
            with self.assertRaises(ValueError):
                core.decrypt_block(0, bad)

    def test_trace_states_chain_with_plan(self):
        trace = core.trace_block(0x1234, 0xBEEF)
        keys = core.round_keys(0xBEEF)
        for index, step in enumerate(trace["plan"]):
            self.assertEqual(trace["states"][index + 1], core.apply_step(trace["states"][index], step, keys))
        self.assertEqual(trace["result"], core.encrypt_block(0x1234, 0xBEEF))


class ParsingTests(unittest.TestCase):
    def test_parse_binary_and_hex(self):
        self.assertEqual(formats.parse_value("0110111101101011", 16), 0x6F6B)
        self.assertEqual(formats.parse_value("0110 1111 0110 1011", 16), 0x6F6B)
        self.assertEqual(formats.parse_value("6f6b", 16), 0x6F6B)
        self.assertEqual(formats.parse_value("0x6F6B", 16), 0x6F6B)
        self.assertEqual(formats.parse_value("A73B1C27", 32), 0xA73B1C27)

    def test_rejects_wrong_lengths_and_characters(self):
        for bad in ("", "6F6", "6F6B0", "011011110110101", "0110111101101012", "GGGG", None, 123):
            with self.assertRaises(ValueError, msg=repr(bad)):
                formats.parse_value(bad, 16)

    def test_formatting(self):
        self.assertEqual(formats.bits(0x6F6B), "0110111101101011")
        self.assertEqual(formats.grouped_bits(0x6F6B), "0110 1111 0110 1011")
        self.assertEqual(formats.hex_text(0x6B), "006B")
        self.assertEqual(formats.describe(0x6F6B)["hex"], "6F6B")


class IndependentImplementationTests(unittest.TestCase):
    """实现 A、B、C 的代码路径互不相同：整数查表、0/1 字符串、GF 多项式矩阵 + 等价逆算法。"""

    def test_known_vector_on_all_implementations(self):
        for item in IMPLEMENTATIONS.values():
            self.assertEqual(item.encrypt(KNOWN_PLAINTEXT, KNOWN_KEY), KNOWN_CIPHERTEXT, item.key)
            self.assertEqual(item.decrypt(KNOWN_CIPHERTEXT, KNOWN_KEY), KNOWN_PLAINTEXT, item.key)

    def test_random_agreement_and_cross_decryption(self):
        rng = random.Random(2026)
        implementations = list(IMPLEMENTATIONS.values())
        for _ in range(1500):
            plaintext, key = rng.getrandbits(16), rng.getrandbits(16)
            ciphertexts = {item.key: item.encrypt(plaintext, key) for item in implementations}
            self.assertEqual(len(set(ciphertexts.values())), 1, (plaintext, key))
            for sender in implementations:
                for receiver in implementations:
                    self.assertEqual(receiver.decrypt(ciphertexts[sender.key], key), plaintext)

    def test_independent_implementations_reject_invalid_input(self):
        with self.assertRaises(ValueError):
            peer.transform("0110", "0" * 16)
        with self.assertRaises(ValueError):
            peer.transform("0" * 16, "0" * 15 + "2")
        with self.assertRaises(ValueError):
            matrix.encrypt(65536, 0)
        with self.assertRaises(ValueError):
            matrix.decrypt(0, True)

    @SKIP_HEAVY
    def test_all_plaintexts_for_fixed_keys(self):
        for key in (textbook.KEY_EXPANSION_KEY, 0x0000):
            key_bits = format(key, "016b")
            for plaintext in range(1 << 16):
                expected = core.encrypt_block(plaintext, key)
                plain_bits = format(plaintext, "016b")
                self.assertEqual(int(peer.transform(plain_bits, key_bits), 2), expected, (plaintext, key))
                self.assertEqual(matrix.encrypt(plaintext, key), expected, (plaintext, key))
                if plaintext % 64 == 0:  # 解密方向每 64 个明文抽一个，全量往返由其他测试覆盖
                    self.assertEqual(int(peer.transform(format(expected, "016b"), key_bits, True), 2), plaintext)
                    self.assertEqual(matrix.decrypt(expected, key), plaintext)

    @SKIP_HEAVY
    def test_all_keys_for_fixed_plaintext(self):
        for plaintext in (KNOWN_PLAINTEXT,):
            plain_bits = format(plaintext, "016b")
            for key in range(1 << 16):
                expected = core.encrypt_block(plaintext, key)
                key_bits = format(key, "016b")
                self.assertEqual(int(peer.transform(plain_bits, key_bits), 2), expected, (plaintext, key))
                self.assertEqual(matrix.encrypt(plaintext, key), expected, (plaintext, key))
                if key % 16 == 0:
                    self.assertEqual(int(peer.transform(format(expected, "016b"), key_bits, True), 2), plaintext)
                    self.assertEqual(matrix.decrypt(expected, key), plaintext)


if __name__ == "__main__":
    unittest.main()
