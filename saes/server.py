"""只监听本机的标准库 HTTP 服务：静态页面 + JSON 接口。无第三方依赖，不记录用户输入。"""

import argparse
import base64
import binascii
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import core, exchange, modes, multiple, selftest
from .experiments import cbc_tamper_experiment, mitm_example, mitm_experiment
from .formats import bits, describe, hex_text, parse_value
from .implementations import get_implementation
from .visualization import reference_tables, simulate_group, simulate_peers, visual_trace

WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
MAX_REQUEST_BYTES = 262_144
MAX_TEXT_CHARACTERS = 4096
DISCARD_LIMIT = 1 << 20  # 拒绝请求时最多读掉并丢弃的请求体字节数
STATIC_FILES = {"/": ("index.html", "text/html; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8"),
                "/visuals.css": ("visuals.css", "text/css; charset=utf-8"),
                "/common.js": ("common.js", "text/javascript; charset=utf-8"),
                "/visuals.js": ("visuals.js", "text/javascript; charset=utf-8"),
                "/figures.js": ("figures.js", "text/javascript; charset=utf-8"),
                "/charts.js": ("charts.js", "text/javascript; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript; charset=utf-8")}


# ------------------------------------------------------------------ 输入解析
def _text(payload: dict, field: str, name: str, allow_empty: bool = True) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or len(value) > MAX_TEXT_CHARACTERS or (not allow_empty and not value):
        raise ValueError(f"{name}必须是长度不超过 {MAX_TEXT_CHARACTERS} 个字符的{'非空' if not allow_empty else ''}文本")
    return value


def _padding(payload: dict) -> str:
    value = payload.get("padding", "zero")
    if value not in modes.PADDING_SCHEMES:
        raise ValueError("填充方式只能是 zero、pkcs7 或 none")
    return value


def _implementation(payload: dict, field: str = "implementation", default: str = "A"):
    return get_implementation(payload.get(field, default))


def _plaintext_list(payload: dict, field: str = "plaintexts", limit: int = 4096) -> list[int]:
    """明文列表：每行一个 16 位二进制 / 4 位十六进制；也可用 random 指定随机个数。"""
    count = payload.get("random")
    if count is not None:
        if type(count) is not int or not 1 <= count <= limit:
            raise ValueError(f"随机明文个数应在 1–{limit} 之间")
        return [secrets.randbits(16) for _ in range(count)]
    lines = _text(payload, field, "明文列表")
    values = [parse_value(line.strip(), 16, "明文") for line in lines.splitlines() if line.strip()]
    if not 1 <= len(values) <= limit:
        raise ValueError(f"明文列表需要 1–{limit} 行")
    return values


def _pair_lines(value) -> list[tuple[int, int]]:
    """明密文对：每行「明文 密文」。"""
    if isinstance(value, list):
        return [(parse_value(item.get("plaintext"), 16, "明文"), parse_value(item.get("ciphertext"), 16, "密文"))
                for item in value if isinstance(item, dict)]
    if not isinstance(value, str) or len(value) > MAX_TEXT_CHARACTERS:
        raise ValueError("请每行输入一对 16 位明文和密文，以空格分隔")
    pairs = []
    for number, line in enumerate(value.splitlines(), 1):
        parts = line.split("#", 1)[0].replace(",", " ").split()
        if not parts:
            continue
        if len(parts) != 2:
            raise ValueError(f"第 {number} 行需要两列：明文 密文")
        pairs.append((parse_value(parts[0], 16, "明文"), parse_value(parts[1], 16, "密文")))
    return pairs


def _decode_cipher_blocks(payload: dict) -> list[int]:
    """密文输入：十六进制（每 4 位一个分组）或 Base64。"""
    text = _text(payload, "cipher", "密文", allow_empty=False)
    kind = payload.get("cipher_format", "hex")
    try:
        data = bytes.fromhex("".join(text.split())) if kind == "hex" else base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("密文格式不正确：十六进制需要偶数个 0–9/A–F 字符，Base64 需要有效编码") from error
    return modes.bytes_to_blocks(data)


# ------------------------------------------------------------------ 各关接口
def handle_block(payload: dict) -> dict:
    block, key = parse_value(payload.get("block"), 16, "数据"), parse_value(payload.get("key"), 16, "密钥")
    cipher = _implementation(payload)
    operation = payload.get("operation")
    if operation not in ("encrypt", "decrypt"):
        raise ValueError("请选择加密或解密")
    result = cipher.encrypt(block, key) if operation == "encrypt" else cipher.decrypt(block, key)
    return {"operation": operation, "implementation": cipher.key, "input": describe(block), "key": describe(key),
            "result": describe(result), "round_keys": [describe(item) for item in core.round_keys(key)]}


def handle_group(payload: dict) -> dict:
    return simulate_group(parse_value(payload.get("key"), 16, "密钥"), _plaintext_list(payload))


def handle_simulate(payload: dict) -> dict:
    return simulate_peers(parse_value(payload.get("key"), 16, "密钥"), _plaintext_list(payload, limit=256),
                          payload.get("group_a", "A"), payload.get("group_b", "C"))


def handle_export(payload: dict) -> dict:
    return exchange.make_exchange(parse_value(payload.get("key"), 16, "密钥"), _plaintext_list(payload, limit=1024),
                                  _implementation(payload))


def handle_verify(payload: dict) -> dict:
    cipher = _implementation(payload)
    if isinstance(payload.get("document"), dict):
        return exchange.verify_exchange(payload["document"], cipher)
    return exchange.verify_vectors(exchange.parse_vector_lines(_text(payload, "lines", "测试向量")), cipher)


def _block_row(index: int, plain_block: int, cipher_block: int) -> dict:
    plain_bytes = plain_block.to_bytes(2, "big")
    return {"index": index, "plain_hex": plain_bytes.hex().upper(), "plain_view": modes.printable_view(plain_bytes),
            "plain_block": hex_text(plain_block), "cipher_block": hex_text(cipher_block),
            "cipher_view": modes.printable_view(cipher_block.to_bytes(2, "big"))}


def handle_ascii(payload: dict) -> dict:
    key, padding, cipher = parse_value(payload.get("key"), 16, "密钥"), _padding(payload), _implementation(payload)
    if payload.get("operation") == "encrypt":
        data = modes.text_to_bytes(_text(payload, "text", "明文"))
        padded = modes.pad(data, padding)
        blocks = modes.ecb_encrypt(data, key, padding, cipher)
        cipher_bytes = modes.blocks_to_bytes(blocks)
        return {"operation": "encrypt", "plain_bytes": len(data), "padded_bytes": len(padded),
                "blocks": [_block_row(index, plain, encrypted)
                           for index, (plain, encrypted) in enumerate(zip(modes.bytes_to_blocks(padded), blocks))],
                "cipher_hex": cipher_bytes.hex().upper(), "cipher_base64": base64.b64encode(cipher_bytes).decode("ascii"),
                "cipher_view": modes.printable_view(cipher_bytes)}
    if payload.get("operation") == "decrypt":
        blocks = _decode_cipher_blocks(payload)
        decrypted = modes.blocks_to_bytes([cipher.decrypt(block, key) for block in blocks])
        try:
            plain = modes.unpad(decrypted, padding)
            padding_ok = True
        except ValueError:
            plain, padding_ok = decrypted, False
        return {"operation": "decrypt", "text": modes.bytes_to_text(plain), "plain_hex": plain.hex().upper(),
                "padding_ok": padding_ok, "plain_bytes": len(plain),
                "blocks": [_block_row(index, cipher.decrypt(block, key), block) for index, block in enumerate(blocks)]}
    raise ValueError("请选择加密或解密")


def handle_double(payload: dict) -> dict:
    key, block, cipher = parse_value(payload.get("key"), 32, "32 位密钥"), parse_value(payload.get("block"), 16, "数据"), _implementation(payload)
    k1, k2 = multiple.split_key(key, 2)
    if payload.get("operation") == "encrypt":
        middle = cipher.encrypt(block, k1)
        steps = [("E_K1", block, k1, middle), ("E_K2", middle, k2, cipher.encrypt(middle, k2))]
    elif payload.get("operation") == "decrypt":
        middle = cipher.decrypt(block, k2)
        steps = [("D_K2", block, k2, middle), ("D_K1", middle, k1, cipher.decrypt(middle, k1))]
    else:
        raise ValueError("请选择加密或解密")
    return {"operation": payload["operation"], "key": describe(key, 32), "k1": describe(k1), "k2": describe(k2),
            "input": describe(block), "result": describe(steps[-1][3]),
            "steps": [{"name": name, "input": describe(value), "key": describe(step_key), "output": describe(output)}
                      for name, value, step_key, output in steps]}


def handle_triple(payload: dict) -> dict:
    mode = payload.get("mode")
    if mode not in multiple.TRIPLE_MODES:
        raise ValueError("三重加密模式只能是 ede2（32 位密钥）或 ede3（48 位密钥）")
    width = multiple.TRIPLE_MODES[mode]
    key, block, cipher = parse_value(payload.get("key"), width, f"{width} 位密钥"), parse_value(payload.get("block"), 16, "数据"), _implementation(payload)
    k1, k2, k3 = multiple.triple_keys(key, mode)
    if payload.get("operation") == "encrypt":
        plan = [("E_K1", cipher.encrypt, k1), ("D_K2", cipher.decrypt, k2), ("E_K3" if mode == "ede3" else "E_K1", cipher.encrypt, k3)]
    elif payload.get("operation") == "decrypt":
        plan = [("D_K3" if mode == "ede3" else "D_K1", cipher.decrypt, k3), ("E_K2", cipher.encrypt, k2), ("D_K1", cipher.decrypt, k1)]
    else:
        raise ValueError("请选择加密或解密")
    steps, value = [], block
    for name, function, step_key in plan:
        output = function(value, step_key)
        steps.append({"name": name, "input": describe(value), "key": describe(step_key), "output": describe(output)})
        value = output
    return {"operation": payload["operation"], "mode": mode, "key": describe(key, width),
            "subkeys": [describe(item) for item in (k1, k2, k3)], "input": describe(block), "result": describe(value),
            "steps": steps}


def handle_mitm_example(payload: dict) -> dict:
    count = payload.get("pairs", 3)
    if type(count) is not int:
        raise ValueError("明密文对数必须是整数")
    example = mitm_example(count)
    return {"key": describe(example["key"], 32),
            "pairs": [{"plaintext": bits(p), "ciphertext": bits(c)} for p, c in example["pairs"]]}


def handle_mitm(payload: dict) -> dict:
    secret = payload.get("secret")
    return mitm_experiment(_pair_lines(payload.get("pairs")),
                           None if not secret else parse_value(secret, 32, "32 位演示密钥"))


def handle_cbc(payload: dict) -> dict:
    key, padding, cipher = parse_value(payload.get("key"), 16, "密钥"), _padding(payload), _implementation(payload)
    iv_text = payload.get("iv")
    iv = parse_value(iv_text, 16, "初始向量") if iv_text else modes.random_iv()
    if payload.get("operation") == "encrypt":
        data = modes.text_to_bytes(_text(payload, "text", "明文"))
        plain_blocks = modes.bytes_to_blocks(modes.pad(data, padding))
        cipher_blocks = modes.cbc_encrypt_blocks(plain_blocks, key, iv, cipher)
        chain = [iv, *cipher_blocks]
        rows = [{"index": index, "plain": hex_text(plain), "previous": hex_text(chain[index]),
                 "xor_input": hex_text(plain ^ chain[index]), "cipher": hex_text(encrypted),
                 "plain_view": modes.printable_view(plain.to_bytes(2, "big"))}
                for index, (plain, encrypted) in enumerate(zip(plain_blocks, cipher_blocks))]
        cipher_bytes = modes.blocks_to_bytes(cipher_blocks)
        ecb_blocks = modes.ecb_encrypt(data, key, padding, cipher)  # 对比：同一明文用 ECB 时重复的明文分组会泄露
        return {"operation": "encrypt", "iv": describe(iv), "rows": rows, "block_count": len(rows),
                "ecb_repeated_blocks": len(ecb_blocks) - len(set(ecb_blocks)),
                "cbc_repeated_blocks": len(cipher_blocks) - len(set(cipher_blocks)),
                "cipher_hex": cipher_bytes.hex().upper(), "cipher_base64": base64.b64encode(cipher_bytes).decode("ascii"),
                "package_hex": (iv.to_bytes(2, "big") + cipher_bytes).hex().upper()}
    if payload.get("operation") == "decrypt":
        blocks = _decode_cipher_blocks(payload)
        plain_blocks = modes.cbc_decrypt_blocks(blocks, key, iv, cipher)
        decrypted = modes.blocks_to_bytes(plain_blocks)
        try:
            plain, padding_ok = modes.unpad(decrypted, padding), True
        except ValueError:
            plain, padding_ok = decrypted, False
        return {"operation": "decrypt", "iv": describe(iv), "text": modes.bytes_to_text(plain), "padding_ok": padding_ok,
                "rows": [{"index": index, "cipher": hex_text(block), "plain": hex_text(value)}
                         for index, (block, value) in enumerate(zip(blocks, plain_blocks))]}
    raise ValueError("请选择加密或解密")


def handle_cbc_tamper(payload: dict) -> dict:
    action = payload.get("action")
    if not isinstance(action, dict):
        raise ValueError("缺少篡改方式")
    data = modes.text_to_bytes(_text(payload, "text", "明文", allow_empty=False))
    return cbc_tamper_experiment(data, parse_value(payload.get("key"), 16, "密钥"), parse_value(payload.get("iv"), 16, "初始向量"),
                                 action, _padding(payload), _implementation(payload))


def handle_selftest(payload: dict) -> dict:
    level = payload.get("level", "all")
    return selftest.run_all() if level == "all" else selftest.run_level(level)


ROUTES = {"/api/visual": lambda p: visual_trace(parse_value(p.get("block"), 16, "分组"), parse_value(p.get("key"), 16, "密钥"),
                                                p.get("operation")),
          "/api/block": handle_block, "/api/group": handle_group, "/api/simulate": handle_simulate,
          "/api/export": handle_export, "/api/verify": handle_verify, "/api/ascii": handle_ascii,
          "/api/double": handle_double, "/api/triple": handle_triple, "/api/mitm/example": handle_mitm_example,
          "/api/mitm": handle_mitm, "/api/cbc": handle_cbc, "/api/cbc/tamper": handle_cbc_tamper,
          "/api/selftest": handle_selftest}


def dispatch(path: str, payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("请求必须是 JSON 对象")
    handler = ROUTES.get(path)
    if handler is None:
        raise ValueError("未知功能")
    return handler(payload)


# ------------------------------------------------------------------ HTTP
class Handler(BaseHTTPRequestHandler):
    def log_message(self, format_string: str, *args) -> None:
        # 默认不输出请求日志，避免演示输入进入终端录屏。
        pass

    def send_content(self, status: int, content: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; "
                         "img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status: int, result: dict) -> None:
        self.send_content(status, json.dumps(result, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def discard_request_body(self) -> None:
        """拒绝请求前先读掉请求体：直接关闭带有未读数据的连接会让客户端收到 TCP 重置，丢失错误响应。"""
        try:
            remaining = min(int(self.headers.get("Content-Length", "0")), DISCARD_LIMIT)
        except ValueError:
            return
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                return
            remaining -= len(chunk)

    def valid_host(self) -> bool:
        port = self.server.server_port
        return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def do_GET(self) -> None:
        if not self.valid_host():
            self.send_json(403, {"error": "仅允许本机访问"})
            return
        path = urlsplit(self.path).path
        if path == "/api/spec":
            self.send_json(200, reference_tables())
            return
        resource = STATIC_FILES.get(path)
        if resource is None:
            self.send_json(404, {"error": "页面不存在"})
            return
        filename, mime = resource
        try:
            content = (WEB_ROOT / filename).read_bytes()
        except OSError:
            self.send_json(404, {"error": "页面文件缺失"})
            return
        self.send_content(200, content, mime)

    def do_POST(self) -> None:
        origin = self.headers.get("Origin")
        allowed = {f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"}
        if not self.valid_host() or (origin is not None and origin not in allowed):
            self.discard_request_body()
            self.send_json(403, {"error": "仅允许本机同源请求"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_REQUEST_BYTES:
                self.discard_request_body()
                raise ValueError(f"请求大小应在 1–{MAX_REQUEST_BYTES} 字节之间")
            payload = json.loads(self.rfile.read(length))
            self.send_json(200, dispatch(urlsplit(self.path).path, payload))
        except (ValueError, UnicodeError) as error:
            self.send_json(400, {"error": str(error)})


def main() -> None:
    parser = argparse.ArgumentParser(description="S-AES 本地实验台（仅监听 127.0.0.1）")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as error:
        parser.exit(1, f"启动失败：{error}；可用 --port 8767 更换端口。\n")
    print(f"S-AES 实验台：http://127.0.0.1:{args.port} （Ctrl+C 退出）", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
