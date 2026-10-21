"""本地 HTTP 接口：路由、输入校验、本机访问限制与安全响应头。"""

import base64
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from saes import server

KEY = "1010011100111011"


class ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_port
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        payload = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode("utf-8"))
        merged = {"Host": f"127.0.0.1:{self.port}", **({"Content-Type": "application/json"} if payload is not None else {}), **(headers or {})}
        connection.request(method, path, body=payload, headers=merged)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, response.headers, data

    def post(self, path, body, expected=200):
        status, _headers, data = self.request("POST", path, body)
        self.assertEqual(status, expected, data.decode("utf-8", "replace"))
        return json.loads(data)


class StaticAndSecurityTests(ServerTestCase):
    def test_every_listed_static_file_is_served_with_security_headers(self):
        for path in server.STATIC_FILES:
            status, headers, data = self.request("GET", path)
            self.assertEqual(status, 200, path)
            self.assertTrue(data, path)
            self.assertIn("charset=utf-8", headers["Content-Type"])
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
            self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])

    def test_index_references_only_listed_files(self):
        _status, _headers, data = self.request("GET", "/")
        html = data.decode("utf-8")
        for path in server.STATIC_FILES:
            if path != "/":
                self.assertIn(f'"{path}"', html, path)

    def test_unlisted_paths_and_traversal_are_not_served(self):
        for path in ("/saes/core.py", "/../saes/core.py", "/%2e%2e/app.py", "/web/index.html", "/nonexistent", "/api/unknown"):
            status, _headers, _data = self.request("GET", path)
            self.assertEqual(status, 404, path)

    def test_query_string_is_ignored_for_static_files(self):
        status, _headers, _data = self.request("GET", "/app.js?run=3")
        self.assertEqual(status, 200)

    def test_only_loopback_host_is_accepted(self):
        for host in ("evil.example", f"evil.example:{self.port}", "127.0.0.1:1"):
            status, _headers, _data = self.request("GET", "/", headers={"Host": host})
            self.assertEqual(status, 403, host)
            status, _headers, _data = self.request("POST", "/api/visual", {"block": "6F6B", "key": "A73B", "operation": "encrypt"}, headers={"Host": host})
            self.assertEqual(status, 403, host)
        status, _headers, _data = self.request("GET", "/", headers={"Host": f"localhost:{self.port}"})
        self.assertEqual(status, 200)

    def test_cross_origin_posts_are_rejected(self):
        body = {"block": "6F6B", "key": "A73B", "operation": "encrypt"}
        status, _headers, _data = self.request("POST", "/api/visual", body, headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        status, _headers, _data = self.request("POST", "/api/visual", body, headers={"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 200)

    def test_malformed_requests_get_a_clear_400(self):
        cases = [(b"", "请求大小"), (b"{not json", None), (b"[1, 2]", "JSON 对象"), (b"x" * (server.MAX_REQUEST_BYTES + 1), "请求大小")]
        for body, message in cases:
            status, _headers, data = self.request("POST", "/api/visual", body)
            self.assertEqual(status, 400)
            self.assertIn("error", json.loads(data))
            if message:
                self.assertIn(message, json.loads(data)["error"])
        self.assertIn("未知功能", self.post("/api/nothing", {}, expected=400)["error"])

    def test_spec_endpoint_returns_the_core_constants(self):
        status, _headers, data = self.request("GET", "/api/spec")
        spec = json.loads(data)
        self.assertEqual(status, 200)
        self.assertEqual(spec["sbox"][0xA], 0)
        self.assertEqual(spec["round_constants"], [0x80, 0x30])


class LevelRouteTests(ServerTestCase):
    def test_visual_trace_route(self):
        trace = self.post("/api/visual", {"block": "6F6B", "key": KEY, "operation": "encrypt"})
        self.assertEqual((trace["result"], len(trace["steps"])), (0x0738, 13))
        decrypted = self.post("/api/visual", {"block": "0738", "key": "A73B", "operation": "decrypt"})
        self.assertEqual(decrypted["result"], 0x6F6B)
        for bad in ({"block": "6F6", "key": KEY, "operation": "encrypt"}, {"block": "6F6B", "key": KEY}, {"block": "6F6B", "key": "xyz", "operation": "decrypt"}):
            self.post("/api/visual", bad, expected=400)

    def test_block_route_with_each_implementation(self):
        for implementation in "ABC":
            result = self.post("/api/block", {"operation": "encrypt", "block": "6F6B", "key": "A73B", "implementation": implementation})
            self.assertEqual(result["result"]["hex"], "0738")
            back = self.post("/api/block", {"operation": "decrypt", "block": "0738", "key": KEY, "implementation": implementation})
            self.assertEqual(back["result"]["hex"], "6F6B")
        self.post("/api/block", {"operation": "encrypt", "block": "6F6B", "key": "A73B", "implementation": "Z"}, expected=400)
        self.post("/api/block", {"operation": "hash", "block": "6F6B", "key": "A73B"}, expected=400)

    def test_group_and_peer_simulation_routes(self):
        group = self.post("/api/group", {"key": KEY, "plaintexts": "6F6B\n0000\nFFFF"})
        self.assertTrue(group["passed"])
        self.assertEqual(group["counts"]["cross_decrypt_total"], 27)
        random_group = self.post("/api/group", {"key": KEY, "random": 50})
        self.assertEqual(random_group["total"], 50)
        peers = self.post("/api/simulate", {"key": KEY, "plaintexts": "6F6B\n1234", "group_a": "B", "group_b": "C"})
        self.assertTrue(peers["passed"])
        self.assertEqual((peers["group_a"]["key"], peers["group_b"]["key"]), ("B", "C"))
        self.post("/api/group", {"key": KEY, "plaintexts": ""}, expected=400)
        self.post("/api/group", {"key": KEY, "random": 0}, expected=400)
        self.post("/api/simulate", {"key": KEY, "plaintexts": "6F6B", "group_a": "Q"}, expected=400)

    def test_exchange_export_and_verify_routes(self):
        document = self.post("/api/export", {"key": KEY, "plaintexts": "6F6B\n0000", "implementation": "C"})
        self.assertEqual(document["vectors"][0]["ciphertext_hex"], "0738")
        self.assertTrue(self.post("/api/verify", {"document": document, "implementation": "B"})["passed"])
        lines = "6F6B A73B 0738\n0000 A73B 0000"
        result = self.post("/api/verify", {"lines": lines})
        self.assertFalse(result["passed"])
        self.assertEqual((result["encrypt_passed"], result["decrypt_passed"]), (1, 1))
        document["spec_id"] = "other"
        self.post("/api/verify", {"document": document}, expected=400)
        self.post("/api/verify", {"lines": "6F6B A73B"}, expected=400)

    def test_ascii_route_round_trips_in_hex_and_base64(self):
        encrypted = self.post("/api/ascii", {"operation": "encrypt", "key": KEY, "text": "Hello, S-AES!"})
        self.assertEqual(encrypted["cipher_hex"], "2B917F2D7CBDBBB52F04658A472C")
        self.assertEqual((encrypted["plain_bytes"], encrypted["padded_bytes"], len(encrypted["blocks"])), (13, 14, 7))
        self.assertEqual(base64.b64decode(encrypted["cipher_base64"]).hex().upper(), encrypted["cipher_hex"])
        for field, key in (("hex", "cipher_hex"), ("base64", "cipher_base64")):
            decrypted = self.post("/api/ascii", {"operation": "decrypt", "key": KEY, "cipher": encrypted[key], "cipher_format": field})
            self.assertEqual(decrypted["text"], "Hello, S-AES!")
            self.assertTrue(decrypted["padding_ok"])
        chinese = self.post("/api/ascii", {"operation": "encrypt", "key": KEY, "text": "信息安全", "padding": "pkcs7"})
        self.assertEqual(self.post("/api/ascii", {"operation": "decrypt", "key": KEY, "cipher": chinese["cipher_hex"], "padding": "pkcs7"})["text"], "信息安全")
        self.post("/api/ascii", {"operation": "encrypt", "key": KEY, "text": "abc", "padding": "none"}, expected=400)
        self.post("/api/ascii", {"operation": "decrypt", "key": KEY, "cipher": "ZZ"}, expected=400)
        self.post("/api/ascii", {"operation": "decrypt", "key": KEY, "cipher": "ABC"}, expected=400)
        self.post("/api/ascii", {"operation": "encrypt", "key": KEY, "text": "x" * 5000}, expected=400)

    def test_double_and_triple_routes(self):
        encrypted = self.post("/api/double", {"operation": "encrypt", "key": "2D55A73B", "block": "6F6B"})
        self.assertEqual(encrypted["result"]["hex"], "1977")
        self.assertEqual([step["name"] for step in encrypted["steps"]], ["E_K1", "E_K2"])
        decrypted = self.post("/api/double", {"operation": "decrypt", "key": "2D55A73B", "block": "1977"})
        self.assertEqual((decrypted["result"]["hex"], decrypted["steps"][0]["name"]), ("6F6B", "D_K2"))
        for mode, key in (("ede2", "2D55A73B"), ("ede3", "2D55A73B1C27")):
            triple = self.post("/api/triple", {"operation": "encrypt", "mode": mode, "key": key, "block": "6F6B"})
            back = self.post("/api/triple", {"operation": "decrypt", "mode": mode, "key": key, "block": triple["result"]["hex"]})
            self.assertEqual(back["result"]["hex"], "6F6B")
        self.post("/api/triple", {"operation": "encrypt", "mode": "ede3", "key": "2D55A73B", "block": "6F6B"}, expected=400)
        self.post("/api/double", {"operation": "encrypt", "key": "2D55", "block": "6F6B"}, expected=400)

    def test_mitm_routes_find_the_secret_key(self):
        example = self.post("/api/mitm/example", {"pairs": 3})
        pairs = "\n".join(f"{int(pair['plaintext'], 2):04X} {int(pair['ciphertext'], 2):04X}" for pair in example["pairs"])
        result = self.post("/api/mitm", {"pairs": pairs, "secret": example["key"]["hex"]})
        self.assertTrue(result["unique"])
        self.assertTrue(result["secret_found"])
        self.assertEqual(result["candidates"][0]["hex"], example["key"]["hex"])
        self.post("/api/mitm", {"pairs": "6F6B"}, expected=400)
        self.post("/api/mitm", {"pairs": ""}, expected=400)
        self.post("/api/mitm/example", {"pairs": 0}, expected=400)

    def test_cbc_routes_and_tamper_experiment(self):
        text = "CBC route test: AAAAAAAAAAAAAAAA end."
        encrypted = self.post("/api/cbc", {"operation": "encrypt", "key": KEY, "iv": "1234", "text": text})
        self.assertEqual(encrypted["iv"]["hex"], "1234")
        self.assertTrue(encrypted["package_hex"].startswith("1234"))
        self.assertGreater(encrypted["ecb_repeated_blocks"], 0)
        self.assertEqual(encrypted["cbc_repeated_blocks"], 0)
        decrypted = self.post("/api/cbc", {"operation": "decrypt", "key": KEY, "iv": "1234", "cipher": encrypted["cipher_hex"]})
        self.assertEqual(decrypted["text"], text)
        wrong_iv = self.post("/api/cbc", {"operation": "decrypt", "key": KEY, "iv": "1235", "cipher": encrypted["cipher_hex"]})
        self.assertEqual(wrong_iv["text"][2:], text[2:])
        self.assertNotEqual(wrong_iv["text"][:2], text[:2])
        random_iv = self.post("/api/cbc", {"operation": "encrypt", "key": KEY, "iv": "", "text": text})
        self.assertEqual(len(random_iv["iv"]["hex"]), 4)
        tamper = self.post("/api/cbc/tamper", {"key": KEY, "iv": "1234", "text": text, "action": {"type": "flip", "index": 2, "bit": 0}})
        self.assertEqual([row["status"] for row in tamper["rows"]][2:4], ["garbled", "bitflip"])
        self.assertEqual(tamper["rows"][3]["xor_difference"], "1000000000000000")
        self.post("/api/cbc/tamper", {"key": KEY, "iv": "1234", "text": text, "action": {"type": "flip", "index": 999, "bit": 0}}, expected=400)
        self.post("/api/cbc/tamper", {"key": KEY, "iv": "1234", "text": text}, expected=400)
        self.post("/api/cbc/tamper", {"key": KEY, "iv": "1234", "text": "", "action": {"type": "flip", "index": 0, "bit": 0}}, expected=400)
        self.post("/api/cbc", {"operation": "decrypt", "key": KEY, "iv": "1234", "cipher": "12"}, expected=400)

    def test_selftest_route(self):
        result = self.post("/api/selftest", {"level": 3})
        self.assertTrue(result["passed"])
        self.assertEqual(result["title"], "扩展功能")
        self.post("/api/selftest", {"level": 9}, expected=400)
        self.post("/api/selftest", {"level": "3"}, expected=400)


if __name__ == "__main__":
    unittest.main()
