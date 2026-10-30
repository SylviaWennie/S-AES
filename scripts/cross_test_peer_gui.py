"""驱动对方的 Tkinter 界面，用我方的测试向量做第 1、3、4、5 关的界面级互测，并给每个页签截图。

用法（仓库根目录，Windows，需要桌面会话）：
    python scripts/cross_test_peer_gui.py --peer-dir <对方仓库的克隆目录>
输出：reports/cross-test-anxayh-gui.json、docs/assets/19–22-peer-gui-*.png
运行期间会弹出对方的窗口约半分钟（其中中间相遇两次各要几秒），请不要操作鼠标键盘，也不要遮挡窗口。
对方的 app.py 只按路径载入、不执行它的 main()；弹出的错误对话框被替换成记录函数，避免阻塞。
"""

import argparse
import ctypes
import importlib.util
import json
import random
import sys
import time
import tkinter as tk
from ctypes import wintypes
from pathlib import Path
from tkinter import ttk

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

from cross_test_peer import PEER_ID, ROOT, SEED, hex_bytes, load_peer, our_cbc_decrypt, our_cbc_encrypt, pack  # noqa: E402
from saes import core, modes, multiple  # noqa: E402
from saes.formats import hex_text  # noqa: E402

H = hex_text
ASSETS = ROOT / "docs" / "assets"
WINDOW_POSITION = "+40+40"


# ------------------------------------------------------------------ 界面操作
def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def press(root: tk.Tk, label: str) -> None:
    """点击界面上文字为 label 的按钮（走 invoke，和用户点击等价），并处理完待办事件。"""
    for widget in walk(root):
        if isinstance(widget, ttk.Button) and widget.cget("text") == label:
            widget.invoke()
            root.update()
            return
    raise LookupError(f"界面上找不到按钮：{label}")


def visible_bounds(root: tk.Tk) -> tuple[int, int, int, int]:
    """窗口（含标题栏）在屏幕上的可见范围，单位是物理像素。"""
    rect = wintypes.RECT()
    handle = ctypes.windll.user32.GetParent(root.winfo_id())
    DWMWA_EXTENDED_FRAME_BOUNDS = 9
    if ctypes.windll.dwmapi.DwmGetWindowAttribute(handle, DWMWA_EXTENDED_FRAME_BOUNDS, ctypes.byref(rect), ctypes.sizeof(rect)) != 0:
        ctypes.windll.user32.GetWindowRect(handle, ctypes.byref(rect))
    return rect.left, rect.top, rect.right, rect.bottom


def snapshot(root: tk.Tk, notebook: ttk.Notebook, tab_index: int, name: str) -> str:
    from PIL import ImageGrab  # 只有截图时才需要

    notebook.select(tab_index)
    root.lift()
    root.focus_force()
    for _ in range(4):
        root.update()
        time.sleep(0.15)
    path = ASSETS / name
    ImageGrab.grab(bbox=visible_bounds(root)).save(path)
    return f"docs/assets/{name}"


# ------------------------------------------------------------------ 各关的界面测试
class Recorder:
    """收集对方界面弹出的错误对话框，而不是真的弹窗。"""

    def __init__(self) -> None:
        self.dialogs: list[dict] = []

    def show_error(self, title, message, **_options) -> None:
        self.dialogs.append({"title": title, "message": message})

    def drain(self) -> list[dict]:
        taken, self.dialogs = self.dialogs, []
        return taken


def level1(root, app, recorder, notebook) -> dict:
    vectors = [(0xD728, 0x4AF5), (0x6F6B, 0xA73B), (0xA749, 0x2D55), (0x0000, 0x0000), (0xFFFF, 0xFFFF), (0x8000, 0x0001), (0x1234, 0xA73B), (0x5A5A, 0x9C1E)]
    rows = []
    for plaintext, key in vectors:
        ours = core.encrypt_block(plaintext, key)
        app.basic_plain.set(H(plaintext))
        app.basic_key.set(H(key))
        press(root, "加密明文")
        shown_cipher = app.basic_cipher.get()
        app.basic_cipher.set(H(ours).lower())  # 把我方的密文（小写）填进对方的“密文”框再解密
        press(root, "解密密文")
        rows.append({"plaintext": H(plaintext), "key": H(key), "ours": H(ours), "gui_encrypt": shown_cipher, "gui_decrypt_of_ours": app.basic_decrypted.get(),
                     "ok": shown_cipher == H(ours) and app.basic_decrypted.get() == H(plaintext)})
        if (plaintext, key) == (0x6F6B, 0xA73B):
            app.basic_cipher.set(shown_cipher)
            screenshot = snapshot(root, notebook, 0, "19-peer-gui-basic.png")
    invalid = []
    for label, plain, key in (("明文含非十六进制字符", "ZZZZ", "4AF5"), ("密钥为 5 位", "D728", "4AF55"), ("明文为空", "", "4AF5")):
        app.basic_plain.set(plain)
        app.basic_key.set(key)
        press(root, "加密明文")
        invalid.append({"case": label, "dialogs": recorder.drain()})
    return {"rows": rows, "invalid": invalid, "screenshot": screenshot}


def level3(root, app, recorder, notebook) -> dict:
    cases = [("Hello, S-AES!", 0xA73B), ("S-AES", 0x4AF5), ("AB", 0x4AF5), ("A", 0xD728), ("", 0x4AF5), ("The quick brown fox.", 0x2D55)]
    rows = []
    for text, key in cases:
        data = text.encode("ascii")
        ours = hex_bytes(modes.blocks_to_bytes(modes.ecb_encrypt(data, key, "zero")))
        app.ascii_message.set(text)
        app.ascii_key.set(H(key))
        press(root, "加密 ASCII")
        shown_cipher, shown_length = app.ascii_cipher.get(), app.ascii_length.get()
        press(root, "解密 ASCII")
        shown_plain = app.ascii_plain_result.get()
        # 把我方的密文换一种写法（小写、无空格）填进去，再让对方界面解密
        app.ascii_cipher.set(ours.replace(" ", "").lower())
        app.ascii_length.set(str(len(data)))
        press(root, "解密 ASCII")
        rows.append({"text": text, "key": H(key), "ours": ours, "gui_cipher": shown_cipher, "gui_length": shown_length,
                     "gui_decrypt_own": shown_plain, "gui_decrypt_ours": app.ascii_plain_result.get(),
                     "ok": shown_cipher == ours and shown_length == str(len(data)) and app.ascii_plain_result.get().startswith(text + "   [HEX:")})
        if text == "Hello, S-AES!":
            app.ascii_message.set(text)
            app.ascii_key.set(H(key))
            press(root, "加密 ASCII")
            press(root, "解密 ASCII")
            screenshot = snapshot(root, notebook, 1, "20-peer-gui-ascii.png")
    app.ascii_message.set("信息")
    press(root, "加密 ASCII")
    return {"rows": rows, "non_ascii_dialogs": recorder.drain(), "screenshot": screenshot}


def level4(root, app, recorder, notebook, rng: random.Random) -> dict:
    operations = {
        "双重加密": lambda p, k1, k2, k3: core.encrypt_block(core.encrypt_block(p, k1), k2),
        "双重解密": lambda p, k1, k2, k3: core.decrypt_block(core.decrypt_block(p, k2), k1),
        "两密钥 EDE 三重加密": lambda p, k1, k2, k3: core.encrypt_block(core.decrypt_block(core.encrypt_block(p, k1), k2), k1),
        "两密钥 EDE 三重解密": lambda p, k1, k2, k3: core.decrypt_block(core.encrypt_block(core.decrypt_block(p, k1), k2), k1),
        "三密钥 EEE 三重加密": lambda p, k1, k2, k3: core.encrypt_block(core.encrypt_block(core.encrypt_block(p, k1), k2), k3),
        "三密钥 EEE 三重解密": lambda p, k1, k2, k3: core.decrypt_block(core.decrypt_block(core.decrypt_block(p, k3), k2), k1),
    }
    rows = []
    for name, expected in operations.items():
        for _ in range(5):
            block, key1, key2, key3 = (rng.randrange(1 << 16) for _ in range(4))
            app.multi_operation.set(name)
            for variable, value in ((app.multi_plain, block), (app.multi_key1, key1), (app.multi_key2, key2), (app.multi_key3, key3)):
                variable.set(H(value))
            press(root, "执行")
            want = H(expected(block, key1, key2, key3))
            rows.append({"operation": name, "input": H(block), "keys": [H(key1), H(key2), H(key3)], "ours": want, "gui": app.multi_result.get(), "ok": app.multi_result.get() == want})

    def run_mitm(true_key1: int, true_key2: int, plaintexts: list[int]) -> dict:
        for (plain_var, cipher_var), plaintext in zip(app.mitm_fields, plaintexts):
            plain_var.set(H(plaintext))
            cipher_var.set(H(multiple.double_encrypt(plaintext, pack(true_key1, true_key2))))
        started = time.perf_counter()
        press(root, "搜索密钥对")
        shown = app.mitm_result.get()
        wanted = f"K1={H(true_key1)} / K2={H(true_key2)}"
        return {"true_key": f"{H(true_key1)}{H(true_key2)}", "pairs": [H(p) for p in plaintexts], "result": shown, "seconds": round(time.perf_counter() - started, 1),
                "ok": shown.startswith("找到 1 组候选密钥") and wanted in shown}

    mitm = [run_mitm(0x2D55, 0xBACE, [0x1234, 0xD728, 0xCAFE]), run_mitm(0xA73B, 0x1C27, [0x6F6B, 0x0000, 0xFFFF])]
    screenshot = snapshot(root, notebook, 2, "21-peer-gui-multiple.png")
    return {"rows": rows, "mitm": mitm, "screenshot": screenshot}


def level5(root, app, recorder, notebook) -> dict:
    message, key, iv = "CBC mode: block chaining test.", 0x4AF5, 0xA1B2
    ours_cipher = our_cbc_encrypt(message.encode(), key, iv)
    app.cbc_message.set(message)
    app.cbc_key.set(H(key))
    app.cbc_iv.set(H(iv))
    press(root, "CBC 加密")
    encrypt_row = {"gui_cipher": app.cbc_ciphertext.get(), "ours": hex_bytes(ours_cipher), "gui_summary": app.cbc_result.get(), "ok": app.cbc_ciphertext.get() == hex_bytes(ours_cipher)}

    other_message, other_key, other_iv = b"Cross-group CBC check!", 0x2D55, 0x7E31
    other_cipher = our_cbc_encrypt(other_message, other_key, other_iv)
    app.cbc_key.set(H(other_key))
    app.cbc_iv.set(H(other_iv).lower())
    app.cbc_ciphertext.set(other_cipher.hex())  # 小写、无空格
    press(root, "CBC 解密")
    decrypt_row = {"gui_result": app.cbc_result.get(), "ok": app.cbc_result.get().startswith(other_message.decode() + "   [HEX:")}

    app.cbc_message.set(message)
    app.cbc_key.set(H(key))
    app.cbc_iv.set("")
    press(root, "CBC 加密")
    random_iv_text = app.cbc_iv.get()
    random_iv_row = {"gui_iv": random_iv_text, "ours_decrypts": our_cbc_decrypt(bytes.fromhex(app.cbc_ciphertext.get().replace(" ", "")), key, int(random_iv_text, 16)) == message.encode()}

    app.cbc_iv.set(H(iv))
    app.cbc_ciphertext.set(hex_bytes(ours_cipher))
    tamper_rows = []
    blocks = modes.bytes_to_blocks(ours_cipher)
    for index, mask in ((3, 0x0001), (0, 0x8000), (len(blocks) - 1, 0x0001)):
        app.cbc_ciphertext.set(hex_bytes(ours_cipher))
        app.cbc_tamper_index.set(str(index))
        app.cbc_tamper_mask.set(H(mask))
        changed = list(blocks)
        changed[index] ^= mask
        expected = None
        try:
            expected = hex_bytes(our_cbc_decrypt(modes.blocks_to_bytes(changed), key, iv))
        except ValueError:
            pass
        press(root, "篡改并解密")
        dialogs = recorder.drain()
        shown = app.cbc_result.get()
        tamper_rows.append({"block_index": index, "mask": H(mask), "ours": expected, "gui_result": shown if not dialogs else None, "dialogs": dialogs,
                            "ok": (expected is not None and shown.endswith(f"[HEX: {expected}]")) if not dialogs else expected is None})
        if index == 3:
            screenshot = snapshot(root, notebook, 3, "22-peer-gui-cbc.png")
    return {"encrypt": encrypt_row, "decrypt": decrypt_row, "random_iv": random_iv_row, "tamper": tamper_rows, "screenshot": screenshot}


def main() -> None:
    parser = argparse.ArgumentParser(description="驱动对方的 Tkinter 界面做界面级互测")
    parser.add_argument("--peer-dir", type=Path, required=True)
    arguments = parser.parse_args()
    peer_dir = arguments.peer_dir.resolve()
    load_peer(peer_dir)
    spec = importlib.util.spec_from_file_location("peer_app", peer_dir / "app.py")
    peer_app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(peer_app)  # 模块名不是 __main__，不会启动 mainloop

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # 截图用物理像素，必须在创建窗口前设置
    except (AttributeError, OSError):
        pass
    recorder = Recorder()
    peer_app.messagebox.showerror = recorder.show_error
    root = tk.Tk()
    root.geometry(WINDOW_POSITION)
    app = peer_app.SAESApp(root)
    root.attributes("-topmost", True)
    root.update()
    time.sleep(0.5)
    rng = random.Random(SEED)
    started = time.perf_counter()
    try:
        results = {"level1": level1(root, app, recorder, app.notebook), "level3": level3(root, app, recorder, app.notebook),
                   "level4": level4(root, app, recorder, app.notebook, rng), "level5": level5(root, app, recorder, app.notebook)}
    finally:
        root.destroy()
    checks = [row["ok"] for row in results["level1"]["rows"] + results["level3"]["rows"] + results["level4"]["rows"] + results["level4"]["mitm"] + results["level5"]["tamper"]]
    checks += [results["level5"]["encrypt"]["ok"], results["level5"]["decrypt"]["ok"], results["level5"]["random_iv"]["ours_decrypts"]]
    output = {"environment": {"tk": tk.TkVersion, "seed": SEED, "elapsed_seconds": round(time.perf_counter() - started)}, "total": len(checks), "passed": sum(checks), **results}
    path = ROOT / "reports" / f"cross-test-{PEER_ID}-gui.json"
    path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"界面级互测：{output['passed']} / {output['total']} 项一致；已保存 {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
