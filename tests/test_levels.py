"""第 2–5 关：交叉测试、字符串、多重加密与中间相遇攻击、CBC 与篡改实验。"""

import random
import unittest

from saes import core, exchange, experiments, modes, multiple
from saes.formats import bits
from saes.implementations import IMPLEMENTATIONS, get_implementation
from saes.visualization import simulate_group, simulate_peers

KEY = 0xA73B


class ExchangeTests(unittest.TestCase):
    def test_export_then_verify_on_every_implementation(self):
        for exporter in IMPLEMENTATIONS.values():
            document = exchange.make_exchange(KEY, [0x0000, 0x6F6B, 0xFFFF], exporter)
            for checker in IMPLEMENTATIONS.values():
                result = exchange.verify_exchange(document, checker)
                self.assertTrue(result["passed"], (exporter.key, checker.key))
                self.assertEqual((result["encrypt_passed"], result["decrypt_passed"]), (3, 3))

    def test_document_carries_conventions_and_both_notations(self):
        document = exchange.make_exchange(KEY, [0x6F6B])
        vector = document["vectors"][0]
        self.assertEqual(document["schema"], exchange.SCHEMA)
        self.assertEqual(vector["ciphertext_hex"], "0738")
        self.assertEqual(vector["ciphertext"], "0000011100111000")
        self.assertIn("sbox", document["conventions"])

    def test_tampered_ciphertext_is_detected_in_both_directions(self):
        document = exchange.make_exchange(KEY, [0x6F6B, 0x1234])
        document["vectors"][0]["ciphertext"] = bits(0x0738 ^ 0x0010)
        result = exchange.verify_exchange(document)
        self.assertFalse(result["passed"])
        self.assertEqual((result["encrypt_passed"], result["decrypt_passed"]), (1, 1))
        self.assertFalse(result["results"][0]["encrypt_ok"])
        self.assertFalse(result["results"][0]["decrypt_ok"])

    def test_different_convention_is_rejected(self):
        document = exchange.make_exchange(KEY, [1])
        document["spec_id"] = "another-spec"
        with self.assertRaisesRegex(ValueError, "算法约定不同"):
            exchange.verify_exchange(document)
        document["spec_id"], document["schema"] = core.SPEC_ID, "other-schema"
        with self.assertRaisesRegex(ValueError, "不支持"):
            exchange.verify_exchange(document)

    def test_malformed_documents_are_rejected(self):
        good = exchange.make_exchange(KEY, [1])
        for mutate in (lambda d: d.update(vectors=[]), lambda d: d.update(vectors=["x"]),
                       lambda d: d.update(vectors=[{"plaintext": "1", "key": "2", "ciphertext": "3"}]),
                       lambda d: d.update(vectors="nope")):
            document = dict(good)
            mutate(document)
            with self.assertRaises(ValueError):
                exchange.verify_exchange(document)
        with self.assertRaises(ValueError):
            exchange.verify_exchange([])
        with self.assertRaises(ValueError):
            exchange.make_exchange(KEY, [])

    def test_text_lines_accept_hex_binary_comments_and_separators(self):
        text = f"6F6B A73B 0738\n\n# 注释行\n{bits(0)},{bits(0)},{bits(core.encrypt_block(0, 0))} # 行内注释\n1234;ABCD;{core.encrypt_block(0x1234, 0xABCD):04x}"
        vectors = exchange.parse_vector_lines(text)
        self.assertEqual(len(vectors), 3)
        self.assertTrue(exchange.verify_vectors(vectors)["passed"])

    def test_text_lines_report_the_bad_line(self):
        with self.assertRaisesRegex(ValueError, "第 2 行"):
            exchange.parse_vector_lines("6F6B A73B 0738\n6F6B A73B")
        with self.assertRaises(ValueError):
            exchange.parse_vector_lines("# 只有注释\n")
        with self.assertRaises(ValueError):
            exchange.parse_vector_lines("6F6B A73B 07zz")


class SimulationTests(unittest.TestCase):
    def test_group_simulation_counts_every_cross_decryption(self):
        rng = random.Random(1)
        result = simulate_group(0x2D55, [rng.getrandbits(16) for _ in range(120)])
        self.assertTrue(result["passed"])
        self.assertEqual(result["counts"], {"encrypt_equal": 120, "cross_decrypt_ok": 1080, "cross_decrypt_total": 1080})
        self.assertEqual({item["key"] for item in result["implementations"]}, {"A", "B", "C"})
        self.assertTrue(all(len(row["cross"]) == 9 for row in result["rows"]))
        self.assertTrue(result["simulation"])

    def test_group_simulation_limits_rows_but_counts_everything(self):
        result = simulate_group(KEY, list(range(300)))
        self.assertEqual((result["total"], result["rows_shown"], len(result["rows"])), (300, 256, 256))
        self.assertEqual(result["counts"]["cross_decrypt_total"], 2700)
        for bad in ([], list(range(4097)), "x", [70000]):
            with self.assertRaises(ValueError):
                simulate_group(KEY, bad)

    def test_peer_simulation_for_every_pair_of_groups(self):
        plaintexts = list(range(0, 65536, 997))
        for group_a in "ABC":
            for group_b in "ABC":
                result = simulate_peers(KEY, plaintexts, group_a, group_b)
                self.assertTrue(result["passed"], (group_a, group_b))
                self.assertEqual(result["counts"], {"encrypt_equal": len(plaintexts), "a_to_b_ok": len(plaintexts),
                                                    "b_to_a_ok": len(plaintexts)})

    def test_peer_simulation_demo_frames_and_notice(self):
        result = simulate_peers(KEY, [0x6F6B], "A", "B")
        self.assertIn("未进行真人跨组测试", result["notice"])
        frames = result["demo"]["a_to_b"]
        self.assertEqual([frame["operation"] for frame in frames], ["encrypt", "transfer", "decrypt"])
        self.assertEqual(frames[0]["output"], "0000011100111000")
        self.assertEqual(frames[2]["output"], bits(0x6F6B))

    def test_peer_simulation_rejects_bad_arguments(self):
        for args in (([], "A", "B"), (list(range(257)), "A", "B"), ([1], "Z", "B"), ([1], "A", "")):
            with self.assertRaises(ValueError):
                simulate_peers(KEY, *args)
        with self.assertRaises(ValueError):
            get_implementation("D")


class TextModeTests(unittest.TestCase):
    def test_blocks_are_two_bytes_high_byte_first(self):
        self.assertEqual(modes.bytes_to_blocks(b"AB\x00\xff"), [0x4142, 0x00FF])
        self.assertEqual(modes.blocks_to_bytes([0x4142, 0x00FF]), b"AB\x00\xff")
        with self.assertRaises(ValueError):
            modes.bytes_to_blocks(b"ABC")

    def test_padding_schemes(self):
        self.assertEqual(modes.pad(b"abc", "zero"), b"abc\x00")
        self.assertEqual(modes.pad(b"ab", "zero"), b"ab")
        self.assertEqual(modes.pad(b"abc", "pkcs7"), b"abc\x01")
        self.assertEqual(modes.pad(b"ab", "pkcs7"), b"ab\x02\x02")
        self.assertEqual(modes.pad(b"ab", "none"), b"ab")
        with self.assertRaises(ValueError):
            modes.pad(b"abc", "none")
        with self.assertRaises(ValueError):
            modes.pad(b"abc", "other")
        for scheme in ("zero", "pkcs7", "none"):
            for data in (b"", b"a", b"ab", b"abc"):
                if scheme == "none" and len(data) % 2:
                    continue
                self.assertEqual(modes.unpad(modes.pad(data, scheme), scheme), data, (scheme, data))

    def test_invalid_pkcs7_padding_is_reported(self):
        for bad in (b"ab\x03\x03", b"ab\x00\x00", b"ab\x01\x02", b""):
            with self.assertRaises(ValueError):
                modes.unpad(bad, "pkcs7")

    def test_unpad_zero_removes_at_most_one_byte(self):
        self.assertEqual(modes.unpad(b"ab\x00\x00", "zero"), b"ab\x00")

    def test_round_trip_for_ascii_and_unicode(self):
        for text in ("", "A", "AB", "Hello, S-AES!", "line1\nline2\ttab", "信息安全 S-AES ✓"):
            for padding in ("zero", "pkcs7"):
                blocks = modes.ecb_encrypt(modes.text_to_bytes(text), KEY, padding)
                self.assertEqual(modes.bytes_to_text(modes.ecb_decrypt(blocks, KEY, padding)), text, (text, padding))

    def test_ascii_string_encrypts_block_by_block(self):
        blocks = modes.ecb_encrypt(b"Hello!", KEY)
        self.assertEqual(blocks, [core.encrypt_block(0x4865, KEY), core.encrypt_block(0x6C6C, KEY),
                                  core.encrypt_block(0x6F21, KEY)])

    def test_identical_blocks_leak_in_ecb(self):
        blocks = modes.ecb_encrypt(b"ABABABAB", KEY)
        self.assertEqual(len(set(blocks)), 1)

    def test_cross_implementation_text(self):
        data = "Cross-implementation text".encode()
        encrypted = modes.ecb_encrypt(data, KEY, "pkcs7", IMPLEMENTATIONS["B"])
        for item in IMPLEMENTATIONS.values():
            self.assertEqual(modes.ecb_decrypt(encrypted, KEY, "pkcs7", item), data)

    def test_printable_view_hides_control_bytes(self):
        self.assertEqual(modes.printable_view(b"A\x00\x7f\xffz"), "A···z")

    def test_wrong_key_on_non_utf8_result_does_not_crash(self):
        blocks = modes.ecb_encrypt(b"secret message", KEY)
        text = modes.bytes_to_text(modes.ecb_decrypt(blocks, KEY ^ 0x00F0))
        self.assertIsInstance(text, str)
        self.assertNotEqual(text, "secret message")


class MultipleEncryptionTests(unittest.TestCase):
    def test_double_encryption_definition_and_key_order(self):
        key = 0x1111_2222
        expected = core.encrypt_block(core.encrypt_block(0x6F6B, 0x1111), 0x2222)  # K1 在高位，先用 K1
        self.assertEqual(multiple.double_encrypt(0x6F6B, key), expected)
        self.assertEqual(multiple.double_decrypt(expected, key), 0x6F6B)
        self.assertNotEqual(multiple.double_encrypt(0x6F6B, 0x2222_1111), expected)

    def test_split_key(self):
        self.assertEqual(multiple.split_key(0xAAAA_BBBB, 2), [0xAAAA, 0xBBBB])
        self.assertEqual(multiple.split_key(0x1111_2222_3333, 3), [0x1111, 0x2222, 0x3333])
        for key, parts in ((1 << 32, 2), (-1, 2), (True, 2), (1 << 48, 3)):
            with self.assertRaises(ValueError):
                multiple.split_key(key, parts)

    def test_triple_encryption_definitions(self):
        e, d = core.encrypt_block, core.decrypt_block
        key2, key3 = 0x1111_2222, 0x1111_2222_3333
        self.assertEqual(multiple.triple_encrypt(0x6F6B, key2, "ede2"), e(d(e(0x6F6B, 0x1111), 0x2222), 0x1111))
        self.assertEqual(multiple.triple_encrypt(0x6F6B, key3, "ede3"), e(d(e(0x6F6B, 0x1111), 0x2222), 0x3333))
        for mode, key in (("ede2", key2), ("ede3", key3)):
            self.assertEqual(multiple.triple_decrypt(multiple.triple_encrypt(0x6F6B, key, mode), key, mode), 0x6F6B)

    def test_triple_modes_validate_their_key_width(self):
        with self.assertRaises(ValueError):
            multiple.triple_encrypt(1, 1 << 32, "ede2")
        with self.assertRaises(ValueError):
            multiple.triple_encrypt(1, 1 << 48, "ede3")
        with self.assertRaises(ValueError):
            multiple.triple_encrypt(1, 1, "eee")

    def test_multiple_encryption_is_implementation_independent(self):
        rng = random.Random(3)
        for _ in range(100):
            block, key32, key48 = rng.getrandbits(16), rng.getrandbits(32), rng.getrandbits(48)
            results = {(multiple.double_encrypt(block, key32, item), multiple.triple_encrypt(block, key32, "ede2", item),
                        multiple.triple_encrypt(block, key48, "ede3", item)) for item in IMPLEMENTATIONS.values()}
            self.assertEqual(len(results), 1)

    def test_meet_in_the_middle_is_sound_and_complete(self):
        example = experiments.mitm_example(1, seed=99)
        (plaintext, ciphertext), = example["pairs"]
        attack = multiple.meet_in_the_middle([(plaintext, ciphertext)])
        found = set(attack["candidates"])
        self.assertIn(example["key"], found)
        self.assertEqual(attack["counts"], [len(found)])
        self.assertGreater(len(found), 1000, "单对明密文应留下大量候选")
        rng = random.Random(4)
        for key in rng.sample(sorted(found), 2000):  # 完整性：每个候选都满足方程
            self.assertEqual(multiple.double_encrypt(plaintext, key), ciphertext)
        # 完备性：不经过攻击代码的查找表，另行按 D_K2(C) 分组，再对抽到的 K1 逐个核对候选集合完全相等
        k2_by_middle = {}
        for k2 in range(1 << 16):
            k2_by_middle.setdefault(core.decrypt_block(ciphertext, k2), []).append(k2)
        found_by_k1 = {}
        for key in found:
            found_by_k1.setdefault(key >> 16, set()).add(key & 0xFFFF)
        for k1 in rng.sample(range(1 << 16), 300):
            expected = set(k2_by_middle.get(core.encrypt_block(plaintext, k1), []))
            self.assertEqual(found_by_k1.get(k1, set()), expected, k1)

    def test_more_pairs_narrow_the_candidates_to_the_secret(self):
        example = experiments.mitm_example(3, seed=100)
        result = experiments.mitm_experiment(example["pairs"], example["key"])
        counts = result["counts"]
        self.assertGreater(counts[0], 1000)
        self.assertLess(counts[1], 50)
        self.assertTrue(counts[0] > counts[1] >= counts[2] >= 1)
        self.assertTrue(result["secret_found"])
        self.assertTrue(result["unique"])
        self.assertEqual(result["candidates"][0]["hex"], format(example["key"], "08X"))
        self.assertGreater(result["speedup"], 10000)
        self.assertEqual(result["table_entries"], 65536)

    def test_meet_in_the_middle_validates_arguments(self):
        for pairs in ([], [(0, 0)] * 17, [(70000, 0)], [(0, -1)]):
            with self.assertRaises(ValueError):
                multiple.meet_in_the_middle(pairs)
        with self.assertRaises(ValueError):
            experiments.mitm_example(0)

    def test_exhaustive_estimate_uses_measured_speed(self):
        estimate = multiple.estimate_exhaustive_seconds(2000)
        self.assertGreater(estimate["per_operation_us"], 0)
        self.assertGreater(estimate["estimated_seconds"], 3600)


class CbcTests(unittest.TestCase):
    def test_definition(self):
        blocks, iv = [0x1111, 0x2222, 0x1111], 0xBEEF
        expected, previous = [], iv
        for block in blocks:
            previous = core.encrypt_block(block ^ previous, KEY)
            expected.append(previous)
        self.assertEqual(modes.cbc_encrypt_blocks(blocks, KEY, iv), expected)
        self.assertEqual(modes.cbc_decrypt_blocks(expected, KEY, iv), blocks)

    def test_round_trip_for_random_messages_and_cipher_choices(self):
        rng = random.Random(8)
        for _ in range(60):
            message = bytes(rng.getrandbits(8) for _ in range(rng.randrange(1, 50))).rstrip(b"\x00") or b"x"
            key, iv = rng.getrandbits(16), modes.random_iv()
            for padding in ("zero", "pkcs7"):
                blocks = modes.cbc_encrypt_bytes(message, key, iv, padding, IMPLEMENTATIONS["A"])
                for item in IMPLEMENTATIONS.values():
                    self.assertEqual(modes.cbc_decrypt_bytes(blocks, key, iv, padding, item), message)

    def test_equal_plaintext_blocks_do_not_repeat(self):
        blocks = modes.cbc_encrypt_bytes(b"A" * 32, KEY, 0x1234)
        self.assertEqual(len(set(blocks)), len(blocks))

    def test_initial_vector_matters_and_only_first_block_depends_on_it(self):
        plain = modes.bytes_to_blocks(b"initial vector!!")
        blocks = modes.cbc_encrypt_blocks(plain, KEY, 0x1234)
        self.assertNotEqual(modes.cbc_encrypt_blocks(plain, KEY, 0x1235), blocks)
        wrong = modes.cbc_decrypt_blocks(blocks, KEY, 0x1235)
        self.assertEqual(wrong[0] ^ plain[0], 0x1234 ^ 0x1235)
        self.assertEqual(wrong[1:], plain[1:])

    def test_random_iv_is_16_bit(self):
        values = {modes.random_iv() for _ in range(50)}
        self.assertTrue(all(0 <= value < 65536 for value in values))
        self.assertGreater(len(values), 25)
        with self.assertRaises(ValueError):
            modes.cbc_encrypt_blocks([1], KEY, 65536)


class TamperExperimentTests(unittest.TestCase):
    MESSAGE = b"Tamper with one CBC ciphertext block, then compare the two decryptions."

    def run_action(self, action):
        return experiments.cbc_tamper_experiment(self.MESSAGE, KEY, 0x4321, action)

    def test_replace_block_garbles_it_and_flips_the_next_one_predictably(self):
        result = self.run_action({"type": "replace", "index": 4, "other": 1})
        rows = result["rows"]
        self.assertEqual(result["changed_cipher_blocks"], [4])
        self.assertEqual(rows[4]["status"], "garbled")
        self.assertEqual(rows[5]["status"], "bitflip")
        self.assertTrue(rows[5]["prediction_matches"])
        delta = int(result["cipher_blocks"][4], 2) ^ int(result["cipher_blocks"][1], 2)
        self.assertEqual(int(rows[5]["xor_difference"], 2), delta)
        self.assertEqual([row["status"] for index, row in enumerate(rows) if index not in (4, 5)],
                         ["intact"] * (len(rows) - 2))
        self.assertEqual(result["summary"], {"intact": len(rows) - 2, "garbled": 1, "bitflip": 1})
        self.assertNotEqual(result["tampered_text"], result["original_text"])
        self.assertEqual(result["original_text"], self.MESSAGE.decode())

    def test_flip_one_bit_changes_exactly_that_bit_in_the_next_plaintext_block(self):
        result = self.run_action({"type": "flip", "index": 2, "bit": 0})
        rows = result["rows"]
        self.assertEqual(rows[3]["xor_difference"], "1000000000000000")
        self.assertGreater(rows[2]["xor_difference"].count("1"), 1)  # 被改密文分组对应的明文整块混乱，不只变一位

    def test_set_value_and_swap(self):
        result = self.run_action({"type": "set", "index": 0, "value": 0xDEAD})
        self.assertEqual(result["tampered_blocks"][0], bits(0xDEAD))
        self.assertEqual(result["rows"][0]["status"], "garbled")
        self.assertEqual(result["rows"][1]["status"], "bitflip")
        swapped = self.run_action({"type": "swap", "index": 2, "other": 5})
        self.assertEqual(swapped["changed_cipher_blocks"], [2, 5])
        self.assertEqual([row["status"] for row in swapped["rows"][2:7]], ["garbled", "bitflip", "intact", "garbled", "bitflip"])

    def test_adjacent_swap_garbles_both_and_flips_the_following_block(self):
        result = self.run_action({"type": "swap", "index": 3, "other": 4})
        statuses = [row["status"] for row in result["rows"]]
        self.assertEqual(statuses[3:6], ["garbled", "garbled", "bitflip"])
        self.assertTrue(result["rows"][5]["prediction_matches"])

    def test_no_op_tamper_changes_nothing(self):
        result = self.run_action({"type": "replace", "index": 3, "other": 3})
        self.assertEqual(result["changed_cipher_blocks"], [])
        self.assertEqual(result["summary"]["intact"], result["block_count"])
        self.assertEqual(result["tampered_text"], result["original_text"])

    def test_cbc_hides_repetition_that_ecb_reveals(self):
        result = experiments.cbc_tamper_experiment(b"A" * 16, KEY, 1, {"type": "flip", "index": 0, "bit": 0})
        self.assertEqual(len(set(result["ecb_blocks"])), 1)
        self.assertEqual(len(set(result["cipher_blocks"])), 8)

    def test_tampering_the_last_block_can_break_pkcs7_padding(self):
        result = experiments.cbc_tamper_experiment(b"abcd", KEY, 7, {"type": "set", "index": 2, "value": 0x1234}, "pkcs7")
        self.assertTrue(result["padding_broken"])

    def test_invalid_actions_are_rejected(self):
        for action in ({"type": "erase", "index": 0}, {"type": "flip", "index": 99, "bit": 0},
                       {"type": "flip", "index": 0, "bit": 16}, {"type": "replace", "index": 0},
                       {"type": "set", "index": 0, "value": 70000}, {"type": "swap", "index": 0, "other": -1},
                       {"index": 0}):
            with self.assertRaises(ValueError, msg=str(action)):
                self.run_action(action)


if __name__ == "__main__":
    unittest.main()
