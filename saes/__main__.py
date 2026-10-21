"""命令行入口：python -m saes <命令>。只是接口层的薄封装，输入检查与计算全部复用 saes.server.dispatch。"""

import argparse
import json
import sys
from pathlib import Path

from .server import dispatch


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m saes", description="S-AES 命令行工具（数据均可写成 16 位二进制或 4 位十六进制）")
    commands = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (("encrypt", "加密一个 16 位分组"), ("decrypt", "解密一个 16 位分组")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("block")
        command.add_argument("key")
        command.add_argument("--impl", default="A", choices="ABC", help="选择实现 A / B / C")
    trace = commands.add_parser("trace", help="输出图解的 13 个步骤")
    trace.add_argument("block")
    trace.add_argument("key")
    trace.add_argument("--decrypt", action="store_true")

    for name in ("ascii-encrypt", "ascii-decrypt", "cbc-encrypt", "cbc-decrypt"):
        command = commands.add_parser(name, help="字符串加解密（第 3 关）" if name.startswith("ascii") else "CBC 加解密（第 5 关）")
        command.add_argument("key")
        if name.startswith("cbc"):
            command.add_argument("iv", help="16 位初始向量；加密时可写 - 表示随机生成")
        command.add_argument("data", help="明文文本，或密文（十六进制 / Base64）")
        command.add_argument("--padding", default="zero", choices=("zero", "pkcs7", "none"))
        command.add_argument("--format", default="hex", choices=("hex", "base64"), help="解密时密文的编码")

    for name in ("double-encrypt", "double-decrypt"):
        command = commands.add_parser(name, help="双重加解密，32 位密钥 K1‖K2")
        command.add_argument("key")
        command.add_argument("block")
    for name in ("triple-encrypt", "triple-decrypt"):
        command = commands.add_parser(name, help="三重加解密")
        command.add_argument("mode", choices=("ede2", "ede3"))
        command.add_argument("key", help="ede2：32 位；ede3：48 位")
        command.add_argument("block")

    mitm = commands.add_parser("mitm", help="中间相遇攻击：文件每行「明文 密文」")
    mitm.add_argument("pairs_file", type=Path)
    export = commands.add_parser("export", help="生成交换文件（JSON）")
    export.add_argument("key")
    export.add_argument("plaintexts", nargs="+")
    export.add_argument("--impl", default="A", choices="ABC")
    verify = commands.add_parser("verify", help="核验交换文件（JSON）或每行「明文 密钥 密文」的文本")
    verify.add_argument("file", type=Path)
    verify.add_argument("--impl", default="A", choices="ABC")
    selftest = commands.add_parser("selftest", help="运行五关自检")
    selftest.add_argument("level", nargs="?", default="all", help="1–5 或 all")
    return parser


def build_request(args: argparse.Namespace) -> tuple[str, dict]:
    command = args.command
    if command in ("encrypt", "decrypt"):
        return "/api/block", {"operation": command, "block": args.block, "key": args.key, "implementation": args.impl}
    if command == "trace":
        return "/api/visual", {"operation": "decrypt" if args.decrypt else "encrypt", "block": args.block, "key": args.key}
    if command.startswith("ascii-"):
        operation = command.split("-")[1]
        field = "text" if operation == "encrypt" else "cipher"
        return "/api/ascii", {"operation": operation, field: args.data, "key": args.key, "padding": args.padding,
                              "cipher_format": args.format}
    if command.startswith("cbc-"):
        operation = command.split("-")[1]
        field = "text" if operation == "encrypt" else "cipher"
        return "/api/cbc", {"operation": operation, field: args.data, "key": args.key, "iv": "" if args.iv == "-" else args.iv,
                            "padding": args.padding, "cipher_format": args.format}
    if command.startswith("double-"):
        return "/api/double", {"operation": command.split("-")[1], "key": args.key, "block": args.block}
    if command.startswith("triple-"):
        return "/api/triple", {"operation": command.split("-")[1], "mode": args.mode, "key": args.key, "block": args.block}
    if command == "mitm":
        return "/api/mitm", {"pairs": args.pairs_file.read_text(encoding="utf-8-sig")}
    if command == "export":
        return "/api/export", {"key": args.key, "plaintexts": "\n".join(args.plaintexts), "implementation": args.impl}
    if command == "verify":
        text = args.file.read_text(encoding="utf-8-sig")
        body = {"document": json.loads(text)} if text.lstrip().startswith("{") else {"lines": text}
        return "/api/verify", {**body, "implementation": args.impl}
    level = args.level if args.level == "all" else int(args.level)
    return "/api/selftest", {"level": level}


def main() -> None:
    # Windows 控制台或管道的默认编码可能是 GBK，无法输出上标等符号，也会让中文错误信息乱码
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args()
    try:
        path, payload = build_request(args)
        result = dispatch(path, payload)
    except (ValueError, OSError) as error:
        parser.exit(2, f"输入错误：{error}\n")
    if path == "/api/mitm":
        result["candidates"] = result["candidates"][:8]  # 命令行只显示前几个候选
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if path in ("/api/verify", "/api/selftest") and not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
