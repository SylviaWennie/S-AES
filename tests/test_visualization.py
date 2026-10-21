"""图解数据：每个步骤里前端要画的数字，都用教材定义独立重算一遍。"""

import unittest

from saes import core
from saes.visualization import reference_tables, visual_trace

from . import textbook

PLAINTEXT, KEY, CIPHERTEXT = 0x6F6B, 0xA73B, 0x0738


def nibbles(state: int) -> list[int]:
    return [(state >> shift) & 0xF for shift in (12, 8, 4, 0)]


def join(values: list[int]) -> int:
    return (values[0] << 12) | (values[1] << 8) | (values[2] << 4) | values[3]


def textbook_sbox(value: int, rows: tuple[str, ...]) -> int:
    return int(rows[value >> 2][value & 3], 16)


class StructureTests(unittest.TestCase):
    def setUp(self):
        self.encrypt = visual_trace(PLAINTEXT, KEY, "encrypt")
        self.decrypt = visual_trace(CIPHERTEXT, KEY, "decrypt")

    def test_thirteen_steps_in_computation_order(self):
        for trace in (self.encrypt, self.decrypt):
            steps = trace["steps"]
            self.assertEqual([step["phase"] for step in steps], ["structure"] + ["key"] * 4 + ["cipher"] * 8)
            self.assertEqual(len({step["id"] for step in steps}), 13)
        self.assertEqual([step["kind"] for step in self.encrypt["steps"][5:]],
                         ["add_key", "substitute", "shift_rows", "mix_columns", "add_key", "substitute", "shift_rows", "add_key"])
        self.assertEqual([step["kind"] for step in self.decrypt["steps"][5:]],
                         ["add_key", "inv_shift_rows", "inv_substitute", "add_key", "inv_mix_columns", "inv_shift_rows",
                          "inv_substitute", "add_key"])

    def test_groups_follow_the_textbook_figure(self):
        # 图 D.1：加密第 2 轮包含最后的 A_K2；解密的 A_K2 在轮外，A_K0 在两轮之后
        self.assertEqual([step["group"] for step in self.encrypt["steps"][5:]],
                         ["pre", "round1", "round1", "round1", "round1", "round2", "round2", "round2"])
        self.assertEqual([step["group"] for step in self.decrypt["steps"][5:]],
                         ["pre", "round1", "round1", "round1", "round1", "round2", "round2", "post"])
        self.assertEqual([step["round"] for step in self.encrypt["steps"][5:]], [0, 1, 1, 1, 1, 2, 2, 2])

    def test_states_chain_and_end_points(self):
        for trace, start in ((self.encrypt, PLAINTEXT), (self.decrypt, CIPHERTEXT)):
            cipher_steps = [step for step in trace["steps"] if step["phase"] == "cipher"]
            self.assertEqual(cipher_steps[0]["before"], start)
            self.assertEqual(cipher_steps[-1]["after"], trace["result"])
            for earlier, later in zip(cipher_steps, cipher_steps[1:]):
                self.assertEqual(earlier["after"], later["before"])
            self.assertEqual([step["before"] for step in cipher_steps] + [trace["result"]], trace["states"])
        self.assertEqual(self.encrypt["result"], CIPHERTEXT)
        self.assertEqual(self.decrypt["result"], PLAINTEXT)

    def test_round_trip_check_runs_the_opposite_operation(self):
        cases = ((self.encrypt, "decrypt", CIPHERTEXT, PLAINTEXT), (self.decrypt, "encrypt", PLAINTEXT, CIPHERTEXT))
        for trace, operation, start, end in cases:
            check = trace["roundtrip"]
            self.assertEqual((check["operation"], check["input"], check["result"], check["matches"]), (operation, start, end, True))
            self.assertEqual((len(check["states"]), check["states"][0], check["states"][-1]), (9, start, end))

    def test_outline_describes_both_directions_for_the_overview_figure(self):
        for trace in (self.encrypt, self.decrypt):
            outline = trace["outline"]
            self.assertEqual([item["kind"] for item in outline["encrypt"]],
                             ["add_key", "substitute", "shift_rows", "mix_columns", "add_key", "substitute", "shift_rows", "add_key"])
            self.assertEqual([item["label"] for item in outline["decrypt"]],
                             ["A_K2", "ISR", "INS", "A_K1", "IMC", "ISR", "INS", "A_K0"])
            self.assertEqual([item["key_name"] for item in outline["encrypt"] if item["key_name"]], ["K0", "K1", "K2"])
        live = [step for step in self.decrypt["steps"] if step["phase"] == "cipher"]
        for step, item in zip(live, self.decrypt["outline"]["decrypt"]):
            self.assertEqual((step["label"], step["group"], step["name"], step["round"]),
                             (item["label"], item["group"], item["name"], item["round"]))

    def test_round_keys_are_used_in_the_right_order(self):
        keys = [step["key_name"] for step in self.encrypt["steps"] if step.get("kind") == "add_key"]
        self.assertEqual(keys, ["K0", "K1", "K2"])
        keys = [step["key_name"] for step in self.decrypt["steps"] if step.get("kind") == "add_key"]
        self.assertEqual(keys, ["K2", "K1", "K0"])
        self.assertEqual(self.encrypt["round_keys"], [0xA73B, 0x1C27, 0x7651])
        self.assertEqual(self.encrypt["words"], [0xA7, 0x3B, 0x1C, 0x27, 0x76, 0x51])

    def test_structure_step_carries_raw_values(self):
        step = self.encrypt["steps"][0]
        self.assertEqual((step["block"], step["key"], step["kind"]), (PLAINTEXT, KEY, "structure"))
        self.assertEqual(self.decrypt["steps"][0]["block_name"], "密文")

    def test_invalid_input(self):
        for args in ((70000, KEY, "encrypt"), (PLAINTEXT, -1, "encrypt"), (PLAINTEXT, KEY, "both"), (True, KEY, "encrypt")):
            with self.assertRaises(ValueError):
                visual_trace(*args)


class KeyExpansionStepTests(unittest.TestCase):
    def test_appendix_example_values(self):
        steps = visual_trace(0x1234, textbook.KEY_EXPANSION_KEY)["steps"][1:5]
        results = [format(step["result"], "08b") for step in steps]
        self.assertEqual(results, list(textbook.KEY_EXPANSION_WORDS))
        self.assertEqual([step["target"] for step in steps], [2, 3, 4, 5])
        self.assertEqual([step["known"] for step in steps], [[0, 1, 2], [0, 1, 2, 3], [0, 1, 2, 3, 4], [0, 1, 2, 3, 4, 5]])

    def test_g_function_details(self):
        steps = visual_trace(0x1234, textbook.KEY_EXPANSION_KEY)["steps"][1:5]
        first, second = steps[0]["g"], steps[2]["g"]
        self.assertEqual(format(first["rotated"], "08b"), "01010101")
        self.assertEqual(format(first["substituted"], "08b"), "00010001")  # 教材：SubNib(01010101) = 00010001
        self.assertEqual((first["round_index"], first["round_constant"]), (1, 0x80))
        self.assertEqual(format(first["output"], "08b"), "10010001")
        self.assertEqual(format(second["input"], "08b"), "11101001")
        self.assertEqual(format(second["rotated"], "08b"), "10011110")
        self.assertEqual(format(second["substituted"], "08b"), "00101111")
        self.assertEqual((second["round_index"], second["round_constant"]), (2, 0x30))
        self.assertIsNone(steps[1]["g"])
        self.assertIsNone(steps[3]["g"])

    def test_operands_reproduce_the_formulas(self):
        steps = visual_trace(0, 0xA73B)["steps"][1:5]
        self.assertEqual(steps[0]["left"] ^ steps[0]["g"]["output"], steps[0]["result"])  # w2 = w0 ⊕ g(w1)
        self.assertEqual(steps[1]["left"] ^ steps[1]["right"], steps[1]["result"])  # w3 = w2 ⊕ w1
        self.assertEqual(steps[2]["left"] ^ steps[2]["g"]["output"], steps[2]["result"])  # w4 = w2 ⊕ g(w3)
        self.assertEqual(steps[3]["left"] ^ steps[3]["right"], steps[3]["result"])  # w5 = w4 ⊕ w3
        for step in steps:
            if step["g"]:
                for lookup, value in zip(step["g"]["lookups"], (step["g"]["rotated"] >> 4, step["g"]["rotated"] & 15)):
                    self.assertEqual((lookup["input"], lookup["output"]), (value, textbook_sbox(value, textbook.SBOX_ROWS)))


class CipherStepDetailTests(unittest.TestCase):
    """用教材定义（而不是 saes.core 的函数）重算每一步，核对前端要画的数字。"""

    def check_trace(self, block: int, key: int, operation: str):
        trace = visual_trace(block, key, operation)
        for step in trace["steps"][5:]:
            before, after = nibbles(step["before"]), nibbles(step["after"])
            kind = step["kind"]
            if kind == "add_key":
                key_nibbles = nibbles(step["key"])
                self.assertEqual(after, [a ^ b for a, b in zip(before, key_nibbles)])
                self.assertEqual([(item["state"], item["key"], item["result"]) for item in step["xor"]],
                                 list(zip(before, key_nibbles, after)))
                self.assertEqual(step["key"], trace["round_keys"][int(step["key_name"][1])])
            elif kind in ("substitute", "inv_substitute"):
                rows = textbook.SBOX_ROWS if kind == "substitute" else textbook.INV_SBOX_ROWS
                self.assertEqual(after, [textbook_sbox(value, rows) for value in before])
                for item in step["lookups"]:
                    value = before[item["position"]]
                    self.assertEqual((item["input"], item["row"], item["column"], item["output"]),
                                     (value, int(format(value, "04b")[:2], 2), int(format(value, "04b")[2:], 2),
                                      textbook_sbox(value, rows)))
                self.assertEqual(step["table"], [textbook_sbox(value, rows) for value in range(16)])
            elif kind in ("shift_rows", "inv_shift_rows"):
                self.assertEqual(after, [before[index] for index in step["mapping"]])
                self.assertEqual(step["mapping"], [0, 3, 2, 1])
            else:
                matrix = [[1, 4], [4, 1]] if kind == "mix_columns" else [[9, 2], [2, 9]]
                self.assertEqual(step["matrix"], matrix)
                results = []
                for term in step["terms"]:
                    column, row = divmod(term["position"], 2)
                    for index, part in enumerate(term["parts"]):
                        source = 2 * column + index
                        self.assertEqual((part["coefficient"], part["source"], part["value"]),
                                         (matrix[row][index], source, before[source]))
                        self.assertEqual(part["product"], textbook.multiplication(part["coefficient"], part["value"]))
                    self.assertEqual(term["result"], term["parts"][0]["product"] ^ term["parts"][1]["product"])
                    results.append(term["result"])
                self.assertEqual(after, results)
            self.assertEqual(join(after), step["after"])
        return trace

    def test_encryption_details(self):
        for block, key in ((PLAINTEXT, KEY), (0x0000, 0x0000), (0xFFFF, 0xFFFF), (0x1234, 0xBEEF)):
            self.check_trace(block, key, "encrypt")

    def test_decryption_details(self):
        for block, key in ((CIPHERTEXT, KEY), (0x0000, 0x0000), (0xFFFF, 0xFFFF), (0xCAFE, 0xBEEF)):
            self.check_trace(block, key, "decrypt")

    def test_mix_columns_example_from_the_book_appears_in_a_trace(self):
        # 教材例子 [[1,4],[4,1]]·[[6,4],[C,0]] = [[3,4],[7,3]]；找一个让 MC 输入恰为 [[6,4],[C,0]] 的明文
        target = textbook.matrix_to_state(textbook.MIX_COLUMNS_EXAMPLE[0])
        k0, _, _ = core.round_keys(0x2D55)
        # 反推：MC 的输入 = SR(NS(P ⊕ K0))，所以 P = INS(ISR(target)) ⊕ K0
        plaintext = core.substitute_nibbles(core.shift_rows(target), core.INV_SBOX) ^ k0
        trace = visual_trace(plaintext, 0x2D55)
        mix = next(step for step in trace["steps"] if step["kind"] == "mix_columns")
        self.assertEqual(mix["before"], target)
        self.assertEqual(mix["after"], textbook.matrix_to_state(textbook.MIX_COLUMNS_EXAMPLE[1]))
        texts = {part["text"] for term in mix["terms"] for part in term["parts"]}
        self.assertIn("x²·(x³+x²) = x⁵+x⁴ ≡ x²+1 (mod x⁴+x+1)", texts)  # 附件 D.1 的 4·C 推导


class ReferenceTableTests(unittest.TestCase):
    def test_tables_equal_the_textbook(self):
        tables = reference_tables()
        self.assertEqual(tables["sbox"], [textbook_sbox(value, textbook.SBOX_ROWS) for value in range(16)])
        self.assertEqual(tables["inv_sbox"], [textbook_sbox(value, textbook.INV_SBOX_ROWS) for value in range(16)])
        for a in range(16):
            self.assertEqual("".join(format(value, "X") for value in tables["multiplication"][a]), textbook.MULTIPLICATION[a])
        self.assertEqual(tables["mix_matrix"], [[1, 4], [4, 1]])
        self.assertEqual(tables["inv_mix_matrix"], [[9, 2], [2, 9]])
        self.assertEqual(tables["round_constants"], [0x80, 0x30])
        self.assertEqual(tables["modulus"], 0b10011)
        self.assertEqual([item["key"] for item in tables["implementations"]], ["A", "B", "C"])


if __name__ == "__main__":
    unittest.main()
