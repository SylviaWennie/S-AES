// 端到端浏览器检查：启动本地服务和无头 Chrome，按五关依次操作真实页面，核对页面上显示的结果并截图。
// 用法：node scripts/check_ui.mjs [--port 8770] [--assets docs/assets] [--report reports/ui-checks.json] [--attach]
//   --attach  不启动服务，直接使用已经在 --port 上运行的实验台
// 需要 Node 22+、Python 3.10+ 和本机的 Chrome / Edge；不依赖任何 npm 包。
import {spawn} from "node:child_process";
import {mkdirSync, writeFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {launchBrowser} from "./lib/cdp.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const options = {port: 8770, assets: "docs/assets", report: "reports/ui-checks.json", attach: false};
const argv = process.argv.slice(2);
for (let index = 0; index < argv.length; index++) {
  if (argv[index] === "--attach") options.attach = true;
  else if (argv[index].startsWith("--")) options[argv[index].slice(2)] = argv[++index];
}
options.port = Number(options.port);
const assets = path.resolve(root, options.assets);
mkdirSync(assets, {recursive: true});
const base = `http://127.0.0.1:${options.port}`;
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function startServer() {
  const child = spawn(process.env.PYTHON || "python", ["-X", "utf8", "app.py", "--port", String(options.port)], {cwd: root, stdio: "ignore"});
  for (let attempt = 0; attempt < 50; attempt++) {
    try { if ((await fetch(`${base}/`)).ok) return child; } catch (error) { /* 服务还在启动 */ }
    await sleep(200);
  }
  child.kill();
  throw new Error("实验台没有启动");
}

const checks = [];
function check(level, name, passed, detail = "") {
  checks.push({level, name, passed: Boolean(passed), detail});
  console.log(`${passed ? "✓" : "✗"} [${level}] ${name}${detail ? ` — ${detail}` : ""}`);
}

const server = options.attach ? null : await startServer();
const browser = await launchBrowser({width: 1440, height: 1000});
const {page} = browser;
const requests = [];
page.on("Network.requestWillBeSent", (params) => requests.push(params.request.url));

const q = JSON.stringify;
const text = (selector) => page.evaluate(`(document.querySelector(${q(selector)}) || {}).textContent ?? null`);
const textOf = async (selector) => ((await text(selector)) ?? "").replace(/\s+/g, " ").trim();
const click = (selector) => page.evaluate(`document.querySelector(${q(selector)}).click()`);
const setValue = (selector, value) => page.evaluate(`(() => { const e = document.querySelector(${q(selector)}); e.value = ${q(value)};
  e.dispatchEvent(new Event("input", {bubbles: true})); e.dispatchEvent(new Event("change", {bubbles: true})); })()`);
const waitFor = (expression, label, timeout = 40000) => page.waitFor(expression, {label, timeout});
const shot = (name, selector, padding = 4) => page.screenshot(path.join(assets, name), selector ? {selector, padding} : {fullPage: true});
let navigation = 0;
const openTab = async (name) => {
  await page.goto(`${base}/?run=${++navigation}#${name}`); // 查询串不同才会整页重新加载（只改 hash 不触发 load）
  await waitFor(`document.body.dataset.ready === "1"`, "页面脚本就绪");
};
const selectStep = (host, index) => page.evaluate(`(() => { const s = document.querySelector("${host} .viz-stage"); s.value = "${index}"; s.dispatchEvent(new Event("change")); })()`);
const noticeText = async () => (await page.evaluate(`document.getElementById("notice").hidden ? "" : document.getElementById("notice").textContent`)) || "";

try {
  const version = await page.send("Browser.getVersion");

  // ---------------------------------------------------------------- 第 1 关
  await openTab("basic");
  await waitFor(`document.querySelector("#cipher-visual .viz-player")`, "第 1 关图解载入");
  check(1, "默认示例 P=6F6B K=A73B 得到密文 0738", (await textOf("#basic-result-hex")) === "0738", await textOf("#basic-result"));
  check(1, "轮密钥 K0/K1/K2 = A73B / 1C27 / 7651", [await textOf("#basic-k0"), await textOf("#basic-k1"), await textOf("#basic-k2")].join(" ") === "A73B 1C27 7651");
  check(1, "界面显示解密回验一致", (await textOf("#basic-roundtrip")).includes("✓ 与输入一致"), await textOf("#basic-roundtrip"));
  check(1, "图解共 13 步，起点是数据结构（图 D.2）", (await textOf("#cipher-visual .viz-step-count")) === "1 / 13");
  await shot("01-basic.png", "#panel-basic");
  await shot("02-structure-d2.png", "#cipher-visual");

  await selectStep("#cipher-visual", 1);
  check(1, "密钥扩展第 1 步：w2 = 1C（图 D.5）", (await textOf("#cipher-visual .viz-caption")).includes("1C") && (await textOf("#cipher-visual .viz-detail")).includes("0001 1100"));
  await shot("03-key-expansion-d5.png", "#cipher-visual");
  await selectStep("#cipher-visual", 6);
  check(1, "第 1 轮 NS：C850 → C619，S 盒查表高亮", (await textOf("#cipher-visual .viz-caption")).includes("输入 C 8 5 0 → 输出 C 6 1 9") && (await page.evaluate(`document.querySelectorAll("#cipher-visual .sbox-table td.hit").length`)) === 4);
  await shot("04-round-substitute-d3.png", "#cipher-visual");
  await selectStep("#cipher-visual", 8);
  check(1, "第 1 轮 MC：C916 → ECA2，附 GF(2⁴) 推导", (await textOf("#cipher-visual .viz-caption")).includes("输入 C 9 1 6 → 输出 E C A 2") && (await textOf("#cipher-visual .viz-detail")).includes("mod x⁴+x+1"));
  await shot("05-round-mixcolumns-d4.png", "#cipher-visual");

  let walked = true;
  await selectStep("#cipher-visual", 0);
  for (let index = 1; index <= 12; index++) {
    await click("#cipher-visual .viz-next");
    walked = walked && (await page.evaluate(`document.querySelector("#cipher-visual .viz-player").dataset.stepIndex`)) === String(index);
  }
  check(1, "「下一步」逐步走完 13 步，最后停在 13 / 13", walked && (await textOf("#cipher-visual .viz-step-count")) === "13 / 13");
  check(1, "走完后整体结构图的密文端显示 0 7 3 8", (await page.evaluate(`[...document.querySelectorAll("#cipher-visual .viz-overview .viz-terminal.is-done")].some((n) => n.textContent.includes("0 7 3 8"))`)));

  await selectStep("#cipher-visual", 5);
  await click("#cipher-visual .viz-play");
  await sleep(700);
  const playing = (await page.evaluate(`document.querySelector("#cipher-visual .viz-player").dataset.playing`)) === "true";
  const moved = Number(await page.evaluate(`document.querySelector("#cipher-visual .viz-progress").value`)) > 0;
  await click("#cipher-visual .viz-play");
  check(1, "播放 / 暂停：播放时进度条前进，再点一次暂停", playing && moved && (await page.evaluate(`document.querySelector("#cipher-visual .viz-player").dataset.playing`)) === "false");

  await click("#basic-use-result");
  await waitFor(`document.getElementById("basic-result-hex").textContent === "6F6B"`, "结果回填后解密");
  check(1, "「结果回填」切换为解密：0738 → 6F6B", (await textOf("#basic-result-direction")).includes("明文") && (await textOf("#basic-roundtrip")).includes("✓"));
  const decryptTitles = [];
  for (const step of [5, 6, 7, 8, 9]) { await selectStep("#cipher-visual", step); decryptTitles.push(await textOf("#cipher-visual .viz-step-title")); }
  check(1, "解密图解的顺序是 A_K2、ISR、INS、A_K1、IMC…", ["A_K2", "ISR", "INS", "A_K1", "IMC"].every((label, index) => decryptTitles[index].includes(label)), decryptTitles.join(" | "));
  await shot("06-decrypt.png", "#cipher-visual");

  await setValue("#basic-example", "book");
  await waitFor(`document.getElementById("basic-words").textContent.includes("2D 55 BC E9 A3 4A")`, "教材示例载入");
  const bookCaptions = [];
  for (const [step, expected] of [[5, "输入 A 7 4 9 → 输出 8 A 1 C"], [6, "输入 8 A 1 C → 输出 6 0 4 C"], [7, "输入 6 0 4 C → 输出 6 C 4 0"], [8, "输入 6 C 4 0 → 输出 3 7 4 3"]]) {
    await selectStep("#cipher-visual", step);
    bookCaptions.push((await textOf("#cipher-visual .viz-caption")).includes(expected));
  }
  check(1, "教材 D.2.1–D.2.4 的四个示例在同一次运行中依次复现（A749 / 2D55）", bookCaptions.every(Boolean), bookCaptions.join(","));

  await setValue("#basic-block", "123");
  const liveError = (await textOf("#basic-block-info")).includes("需要 16 位二进制或 4 位十六进制");
  await click("#basic-run");
  await waitFor(`!document.getElementById("notice").hidden`, "错误提示");
  check(1, "非法输入：即时提示且提交后显示后端错误", liveError && (await noticeText()).includes("必须是 16 位二进制或 4 位十六进制"), await noticeText());
  await setValue("#basic-block", "0110111101101011");
  await setValue("#basic-key", "1010011100111011");
  await setValue("#basic-operation", "encrypt");
  await waitFor(`document.getElementById("basic-result-hex").textContent === "0738" && document.getElementById("notice").hidden`, "恢复默认输入");

  // ---------------------------------------------------------------- 第 2 关
  await openTab("cross");
  await waitFor(`document.querySelectorAll("#group-table tbody tr").length > 0 && document.querySelector("#peer-visual .viz-player")`, "第 2 关默认运行");
  const groupTiles = async () => [1, 2].map((n) => `#group-summary div:nth-child(${n}) strong`);
  check(2, "组内互验（A/B/C）：8 个明文密文一致、72 次交叉解密全部还原",
    (await textOf((await groupTiles())[0])) === "8 / 8" && (await textOf((await groupTiles())[1])) === "72 / 72");
  check(2, "交叉解密矩阵显示 9 个 ✓", (await page.evaluate(`document.querySelectorAll("#group-matrix td.ok").length`)) === 9);
  await shot("07-cross-group.png", "#group-row");
  await click("#group-random");
  await waitFor(`document.querySelector("#group-summary div:nth-child(1) strong").textContent === "256 / 256"`, "随机 256 个明文");
  check(2, "随机 256 个明文：加密一致 256 / 256，交叉解密 2,304 / 2,304",
    (await textOf((await groupTiles())[1])) === "2,304 / 2,304");

  check(2, "组间互测（A 组实现 A ↔ B 组实现 C）：三项均通过",
    (await Promise.all([1, 2, 3].map((n) => textOf(`#peer-summary div:nth-child(${n}) strong`)))).join("|") === "5 / 5|5 / 5|5 / 5");
  await click("#peer-visual .viz-next");
  await click("#peer-visual .viz-next");
  check(2, "传输动画最后一帧：B 组解密，还原一致 ✓", (await textOf("#peer-visual svg")).includes("还原一致 ✓"));
  await shot("08-cross-peers.png", "#peer-row");
  await shot("08-cross-peers-animation.png", "#peer-visual");
  await setValue("#peer-direction", "b_to_a");
  await click("#peer-visual .viz-next");
  await click("#peer-visual .viz-next");
  check(2, "切换为 B 组加密 → A 组解密，同样还原一致 ✓", (await textOf("#peer-visual svg")).includes("还原一致 ✓"));

  await click("#peer-all");
  await waitFor(`document.querySelector("#peer-summary div:nth-child(1) strong").textContent === "256 / 256"`, "载入 256 个明文");
  check(2, "「载入 256 个明文」：两组 256 / 256 密文一致，两个方向都还原",
    (await Promise.all([1, 2, 3].map((n) => textOf(`#peer-summary div:nth-child(${n}) strong`)))).join("|") === "256 / 256|256 / 256|256 / 256");

  await click("#export-lines");
  await waitFor(`document.getElementById("verify-text").value.split("\\n").length === 4`, "导出纯文本向量");
  await setValue("#verify-impl", "B");
  await click("#verify-run");
  await waitFor(`document.getElementById("verify-result").textContent.includes("共 4 条")`, "核验结果");
  check(2, "交换：实现 A 导出的 4 条向量由实现 B 核验全部通过", (await textOf("#verify-result")).includes("全部通过 · 共 4 条"), await textOf("#verify-result"));
  await page.evaluate(`(() => { const e = document.getElementById("verify-text"); const lines = e.value.split("\\n"); lines[1] = lines[1].replace(/.$/, (c) => (c === "0" ? "1" : "0")); e.value = lines.join("\\n"); })()`);
  await click("#verify-run");
  await waitFor(`document.getElementById("verify-result").textContent.includes("不一致")`, "篡改后核验");
  check(2, "交换：改动一条密文后核验检出不一致", (await textOf("#verify-result")).includes("有 1 条不一致"), await textOf("#verify-result"));
  await shot("09-cross-exchange.png", "#verify-form");

  // ---------------------------------------------------------------- 第 3 关
  await openTab("ascii");
  await waitFor(`document.querySelectorAll("#ascii-table tbody tr").length > 0`, "第 3 关默认运行");
  check(3, "\"Hello, S-AES!\"：13 字节 → 补 1 字节 → 7 个分组",
    (await textOf("#ascii-summary")).startsWith("13明文字节14填充后字节7"));
  check(3, "密文（十六进制）= 2B917F2D7CBDBBB52F04658A472C", (await textOf("#ascii-result")).includes("2B917F2D7CBDBBB52F04658A472C"));
  check(3, "乱码字符串视图显示不可打印字节为 ·", (await textOf("#ascii-result")).includes("·"));
  await shot("10-ascii.png", "#panel-ascii");
  await click("#ascii-refill");
  await waitFor(`document.getElementById("ascii-result").textContent.includes("还原的文本")`, "密文回填解密");
  check(3, "「密文回填解密」还原原文", (await textOf("#ascii-result")).includes('"Hello, S-AES!"'), await textOf("#ascii-result"));
  await setValue("#ascii-operation", "encrypt");
  await setValue("#ascii-text", "信息安全导论");
  await click("#ascii-run");
  await waitFor(`document.getElementById("ascii-result").textContent.includes("密文（十六进制）")`, "中文加密");
  await click("#ascii-refill");
  await waitFor(`document.getElementById("ascii-result").textContent.includes("还原的文本")`, "中文解密");
  check(3, "中文按 UTF-8 加解密往返", (await textOf("#ascii-result")).includes("信息安全导论"));
  await setValue("#ascii-operation", "encrypt");
  await setValue("#ascii-padding", "none");
  await setValue("#ascii-text", "abc");
  await click("#ascii-run");
  await waitFor(`!document.getElementById("notice").hidden`, "无填充奇数字节");
  check(3, "无填充 + 奇数字节：被拒绝并提示", (await noticeText()).includes("偶数"), await noticeText());

  await openTab("ascii");
  await waitFor(`document.querySelectorAll("#ascii-table tbody tr").length === 7`, "第 3 关默认运行");
  await page.evaluate(`document.querySelectorAll("#ascii-table tbody tr")[1].click()`);
  await click("#ascii-inspect");
  await waitFor(`document.getElementById("tab-basic").getAttribute("aria-selected") === "true" && document.querySelector("#cipher-visual .viz-player") && document.getElementById("basic-result-hex").textContent === "7F2D"`, "跳转到第 1 关");
  check(3, "「在第 1 关展开所选分组」：数据为分组 6C6C（“ll”），停在第一个加密变换，密文 7F2D",
    (await page.evaluate(`document.getElementById("basic-block").value`)) === "0110110001101100" && (await page.evaluate(`document.querySelector("#cipher-visual .viz-player").dataset.stepIndex`)) === "5");

  // ---------------------------------------------------------------- 第 4 关
  await openTab("multiple");
  await waitFor(`document.querySelector("#mitm-funnel .funnel-chart") && document.querySelector("#double-result .chain") && document.querySelector("#triple-result .chain")`, "第 4 关默认运行（含中间相遇攻击）");
  check(4, "双重加密 P=6F6B K=2D55A73B → 1977", (await textOf("#double-result .chain-node.end strong")) === "1977");
  check(4, "中间相遇攻击（3 对）：候选数收敛到 1，并包含示例密钥", (await textOf("#mitm-summary div:nth-child(1) strong")) === "1" && (await textOf("#mitm-secret-check")).includes("在候选中 ✓"), await textOf("#mitm-secret-check"));
  check(4, "漏斗图：65,080 → 1 → 1（对数坐标，附表格视图）", (await textOf("#mitm-funnel")).includes("65,080") && (await page.evaluate(`document.querySelectorAll("#mitm-funnel tbody tr").length`)) === 4);
  check(4, "三重加密 EDE2 得到 3218", (await textOf("#triple-result .chain-node.end strong")) === "3218");
  await shot("11-multiple-double.png", "#double-form");
  await shot("12-mitm.png", "#mitm-row");

  await click("#double-use-result");
  await waitFor(`document.querySelector("#double-result .chain-node.end strong") && document.querySelector("#double-result .chain-node.end strong").textContent === "6F6B"`, "双重解密");
  check(4, "双重加密「结果回填」后解密还原 6F6B", (await textOf("#double-result .chain-node.end strong")) === "6F6B");
  await setValue("#triple-mode", "ede3");
  await waitFor(`document.getElementById("triple-key").value.length === 12 && document.getElementById("triple-result").textContent.includes("K3 = 1C27")`, "切换到 48 位模式");
  check(4, "三重加密切换到 48 位密钥模式并重新计算", (await textOf("#triple-formula")).includes("E_K3"), await textOf("#triple-result .chain-node.end strong"));
  await shot("13-triple.png", "#triple-form");

  await page.evaluate(`document.getElementById("mitm-pairs").value = "6F6B 1977"`);
  await click("#mitm-run");
  await waitFor(`document.querySelectorAll("#mitm-funnel tbody tr").length === 2`, "单对攻击");
  const oneCount = Number((await textOf("#mitm-summary div:nth-child(1) strong")).replaceAll(",", ""));
  check(4, "只给 1 对明密文：候选数约 6.5 万，不能唯一确定密钥", oneCount > 60000 && oneCount < 70000, String(oneCount));
  await click("#mitm-example");
  await waitFor(`document.querySelectorAll("#mitm-funnel tbody tr").length === 4 && document.getElementById("mitm-secret-check").textContent.includes("✓")`, "随机示例攻击");
  check(4, "「随机生成示例」：新密钥被唯一找回", (await textOf("#mitm-summary div:nth-child(1) strong")) === "1" && (await textOf("#mitm-secret-check")).includes("在候选中 ✓"), await textOf("#mitm-secret-check"));

  // ---------------------------------------------------------------- 第 5 关
  await openTab("cbc");
  await waitFor(`document.querySelector("#tamper-strip .strip") && document.querySelector("#cbc-decrypt-result .row")`, "第 5 关默认运行");
  check(5, "CBC 加密：33 个分组，ECB 重复分组 7 → CBC 0", (await textOf("#cbc-summary")).startsWith("33") && (await textOf("#cbc-summary")).includes("7 → 0"), await textOf("#cbc-summary"));
  check(5, "传输包 = IV（1234）‖ 密文", await page.evaluate(`document.getElementById("cbc-package").value.startsWith("1234") && document.getElementById("cbc-package").value.length === 4 + 33 * 4`));
  check(5, "CBC 解密还原原文", (await textOf("#cbc-decrypt-result")).includes("CBC mode demo"));
  check(5, "篡改（替换分组 #4）：1 块乱码、1 块位翻转、其余 31 块不变",
    (await page.evaluate(`document.querySelectorAll("#tamper-strip .status-garbled.strip-cell").length`)) === 1
    && (await page.evaluate(`document.querySelectorAll("#tamper-strip .status-bitflip.strip-cell").length`)) === 1
    && (await page.evaluate(`document.querySelectorAll("#tamper-strip .status-intact.strip-cell").length`)) === 31);
  check(5, "状态条用图标 + 文字标注（不只靠颜色）", (await textOf("#tamper-strip .strip-legend")).includes("✓") && (await textOf("#tamper-strip .strip-legend")).includes("✕") && (await textOf("#tamper-strip .strip-legend")).includes("⚠"));
  await shot("14-cbc.png", "#cbc-form");
  await shot("15-cbc-chain.png", "#cbc-chain");
  await page.evaluate(`(() => { const card = document.getElementById("tamper-strip").closest(".card"); card.id = "tamper-card"; })()`);
  await shot("16-cbc-tamper.png", "#tamper-card");

  await setValue("#tamper-action", "flip");
  await setValue("#tamper-index", "10");
  await setValue("#tamper-bit", "0");
  await click("#tamper-run");
  await waitFor(`document.getElementById("tamper-badge").textContent.includes("#10")`, "翻转 1 位");
  check(5, "翻转分组 #10 的最高位：下一个明文分组恰好被翻转 8000", (await textOf("#tamper-notes")).includes("8000"), await textOf("#tamper-badge"));
  await setValue("#tamper-action", "swap");
  await setValue("#tamper-index", "3");
  await setValue("#tamper-other", "6");
  await click("#tamper-run");
  await waitFor(`document.getElementById("tamper-badge").textContent.includes("#6")`, "交换分组");
  check(5, "交换两个分组：两块乱码、其后各有一块位翻转", (await page.evaluate(`document.querySelectorAll("#tamper-strip .status-garbled.strip-cell").length`)) === 2 && (await page.evaluate(`document.querySelectorAll("#tamper-strip .status-bitflip.strip-cell").length`)) === 2);
  await setValue("#cbc-decrypt-iv", "1235");
  await page.evaluate(`document.getElementById("cbc-decrypt-input").value = document.getElementById("cbc-package").value.slice(4)`);
  await click("#cbc-decrypt-run");
  await waitFor(`document.getElementById("cbc-decrypt-result").textContent.includes("1235")`, "错误 IV 解密");
  check(5, "使用错误 IV 解密：只有第 1 个分组出错，后面的文字完好", (await textOf("#cbc-decrypt-result")).includes(" mode demo: AAAAAAAAAAAAAAAA tamper") && !(await textOf("#cbc-decrypt-result")).includes("CBC mode demo"), await textOf("#cbc-decrypt-result"));

  // ---------------------------------------------------------------- 一键闯关
  await openTab("all");
  await click("#all-run");
  await waitFor(`document.querySelectorAll(".level-card").length === 5`, "五关自检", 60000);
  check("总", "一键闯关：5/5 通过", (await textOf("#all-summary strong")) === "5/5", await textOf("#all-summary"));
  check("总", "五个关卡标签都出现 ✓ 标记", (await page.evaluate(`[...document.querySelectorAll(".tabs .pass-mark")].filter((m) => !m.hidden).length`)) === 5);
  await shot("17-all-levels.png", "#panel-all");

  // ---------------------------------------------------------------- 键盘、窄屏、外部请求
  await openTab("basic");
  await page.evaluate(`document.getElementById("tab-basic").focus()`);
  await page.send("Input.dispatchKeyEvent", {type: "keyDown", key: "ArrowRight", code: "ArrowRight", windowsVirtualKeyCode: 39});
  await page.send("Input.dispatchKeyEvent", {type: "keyUp", key: "ArrowRight", code: "ArrowRight", windowsVirtualKeyCode: 39});
  await sleep(200);
  check("总", "键盘：在标签上按 → 切换到下一关", (await page.evaluate(`document.getElementById("tab-cross").getAttribute("aria-selected")`)) === "true");

  await page.setViewport(390, 844, 1, true);
  const overflow = [];
  for (const tab of ["basic", "cross", "ascii", "multiple", "cbc", "all"]) {
    await openTab(tab);
    await sleep(tab === "multiple" ? 4500 : 900);
    overflow.push(`${tab}:${await page.evaluate(`document.documentElement.scrollWidth - window.innerWidth`)}`);
  }
  check("总", "390px 窄屏：六个页面都没有整页横向溢出", overflow.every((item) => Number(item.split(":")[1]) <= 1), overflow.join(" "));
  await openTab("basic");
  await waitFor(`document.querySelector("#cipher-visual .viz-player")`, "窄屏图解");
  await shot("18-mobile.png", null);
  await page.setViewport(1440, 1000, 1, false);

  const external = requests.filter((url) => !url.startsWith(base) && !url.startsWith("data:") && !url.startsWith("about:") && !url.startsWith("blob:"));
  check("总", "页面没有向外部发出任何网络请求", external.length === 0, external.join(" "));
  // 第 1、3 关各做过一次「非法输入」的负面测试，后端按设计返回 400，浏览器会把它记成 console error；这两条属于预期，其余必须为 0
  const expectedErrors = ["/api/visual", "/api/ascii"];
  const unexpected = page.problems.filter((item) => {
    const index = expectedErrors.findIndex((url) => item.includes("400 (Bad Request)") && item.includes(url));
    if (index < 0) return true;
    expectedErrors.splice(index, 1);
    return false;
  });
  check("总", "浏览器控制台与脚本异常为 0（两次预期内的 400 负面测试除外）", unexpected.length === 0 && expectedErrors.length === 0, unexpected.join(" | "));

  const report = {generated_on: new Date().toISOString().slice(0, 10), browser: version.product, viewport: "1440x1000（窄屏检查 390x844）",
    passed: checks.every((item) => item.passed), total: checks.length, checks, console_problems: unexpected, expected_negative_test_responses: 2};
  writeFileSync(path.resolve(root, options.report), JSON.stringify(report, null, 2) + "\n", "utf-8");
  console.log(`\n${report.passed ? "全部通过" : "存在失败项"}：${checks.filter((item) => item.passed).length}/${checks.length}；报告 ${options.report}`);
  process.exitCode = report.passed ? 0 : 1;
} catch (error) {
  console.error("检查中断：", error.message);
  process.exitCode = 1;
} finally {
  await browser.close();
  if (server) server.kill();
}
