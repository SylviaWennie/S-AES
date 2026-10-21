"""命令行：python -m saes。以子进程方式运行，核对输出与退出码。"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEY = "1010011100111011"


def run(*arguments):
    completed = subprocess.run([sys.executable, "-X", "utf8", "-m", "saes", *arguments], cwd=ROOT, capture_output=True, timeout=120)
    return completed.returncode, completed.stdout.decode("utf-8"), completed.stderr.decode("utf-8")


class CommandLineTests(unittest.TestCase):
    def test_encrypt_and_decrypt_accept_binary_and_hex(self):
        for block, key in (("6F6B", "A73B"), ("0110111101101011", KEY)):
            code, out, _err = run("encrypt", block, key)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["result"]["hex"], "0738")
        code, out, _err = run("decrypt", "0738", "A73B", "--impl", "C")
        self.assertEqual((code, json.loads(out)["result"]["hex"]), (0, "6F6B"))

    def test_invalid_input_exits_with_status_2_and_a_readable_message(self):
        code, out, err = run("encrypt", "6F6", "A73B")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("输入错误", err)
        self.assertIn("16 位二进制或 4 位十六进制", err)

    def test_trace_prints_all_thirteen_steps(self):
        code, out, _err = run("trace", "6F6B", "A73B")
        trace = json.loads(out)
        self.assertEqual((code, len(trace["steps"]), trace["result"]), (0, 13, 0x0738))
        decrypt = json.loads(run("trace", "0738", "A73B", "--decrypt")[1])
        self.assertEqual(decrypt["result"], 0x6F6B)

    def test_text_commands_round_trip(self):
        encrypted = json.loads(run("ascii-encrypt", "A73B", "Hello, S-AES!")[1])
        self.assertEqual(encrypted["cipher_hex"], "2B917F2D7CBDBBB52F04658A472C")
        decrypted = json.loads(run("ascii-decrypt", "A73B", encrypted["cipher_hex"])[1])
        self.assertEqual(decrypted["text"], "Hello, S-AES!")
        decrypted = json.loads(run("ascii-decrypt", "A73B", encrypted["cipher_base64"], "--format", "base64")[1])
        self.assertEqual(decrypted["text"], "Hello, S-AES!")

    def test_multiple_encryption_commands(self):
        self.assertEqual(json.loads(run("double-encrypt", "2D55A73B", "6F6B")[1])["result"]["hex"], "1977")
        self.assertEqual(json.loads(run("double-decrypt", "2D55A73B", "1977")[1])["result"]["hex"], "6F6B")
        for mode, key in (("ede2", "2D55A73B"), ("ede3", "2D55A73B1C27")):
            cipher = json.loads(run("triple-encrypt", mode, key, "6F6B")[1])["result"]["hex"]
            self.assertEqual(json.loads(run("triple-decrypt", mode, key, cipher)[1])["result"]["hex"], "6F6B")

    def test_cbc_commands_use_a_random_iv_when_asked(self):
        encrypted = json.loads(run("cbc-encrypt", "A73B", "-", "Hello CBC mode")[1])
        package = encrypted["package_hex"]
        decrypted = json.loads(run("cbc-decrypt", "A73B", package[:4], package[4:])[1])
        self.assertEqual(decrypted["text"], "Hello CBC mode")
        fixed = json.loads(run("cbc-encrypt", "A73B", "1234", "Hello CBC mode")[1])
        self.assertTrue(fixed["package_hex"].startswith("1234"))

    def test_export_then_verify_files(self):
        code, out, _err = run("export", "A73B", "6F6B", "0000", "--impl", "B")
        self.assertEqual(code, 0)
        document = json.loads(out)
        with tempfile.TemporaryDirectory() as folder:
            good = Path(folder, "good.json")
            good.write_text(out, encoding="utf-8")
            self.assertEqual(run("verify", str(good))[0], 0)
            document["vectors"][0]["ciphertext"] = "0000000000000000"
            bad = Path(folder, "bad.json")
            bad.write_text(json.dumps(document), encoding="utf-8")
            code, result, _err = run("verify", str(bad))
            self.assertEqual(code, 1)
            self.assertFalse(json.loads(result)["passed"])
            lines = Path(folder, "vectors.txt")
            lines.write_text("# 注释\n6F6B A73B 0738\n", encoding="utf-8")
            self.assertEqual(run("verify", str(lines))[0], 0)
            self.assertEqual(run("verify", str(Path(folder, "missing.json")))[0], 2)

    def test_mitm_command_reads_pairs_from_a_file(self):
        with tempfile.TemporaryDirectory() as folder:
            pairs = Path(folder, "pairs.txt")
            pairs.write_text("6F6B 1977\n1234 84BA\nBEEF 868E\n", encoding="utf-8")
            code, out, _err = run("mitm", str(pairs))
        result = json.loads(out)
        self.assertEqual((code, result["counts"][-1], result["candidates"][0]["hex"]), (0, 1, "2D55A73B"))

    def test_selftest_command(self):
        code, out, _err = run("selftest", "5")
        self.assertEqual((code, json.loads(out)["passed"]), (0, True))
        self.assertEqual(run("selftest", "9")[0], 2)


if __name__ == "__main__":
    unittest.main()
