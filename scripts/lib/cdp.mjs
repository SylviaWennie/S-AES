// 零依赖的 Chrome DevTools 协议小客户端：启动无头浏览器、执行脚本、截图。
// 需要 Node 22+（内置 WebSocket 和 fetch）与本机安装的 Chrome 或 Edge。
import {spawn} from "node:child_process";
import {existsSync, mkdtempSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import path from "node:path";

const CANDIDATES = [
  process.env.CHROME_PATH,
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
];

export function findBrowser() {
  const found = CANDIDATES.find((candidate) => candidate && existsSync(candidate));
  if (!found) throw new Error("没有找到 Chrome / Edge，请设置环境变量 CHROME_PATH");
  return found;
}

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

export async function launchBrowser({width = 1440, height = 1000, scale = 1} = {}) {
  const profile = mkdtempSync(path.join(tmpdir(), "saes-chrome-"));
  const port = 9300 + Math.floor(Math.random() * 600);
  const child = spawn(findBrowser(), ["--headless=new", `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, "--no-first-run",
    "--disable-gpu", "--hide-scrollbars", "--disable-extensions", `--window-size=${width},${height}`, "about:blank"], {stdio: "ignore"});
  let target = null;
  for (let attempt = 0; attempt < 60 && !target; attempt++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      target = list.find((item) => item.type === "page");
    } catch (error) { /* 浏览器还在启动 */ }
    if (!target) await sleep(250);
  }
  if (!target) { child.kill(); throw new Error("无法连接浏览器调试端口"); }

  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = () => reject(new Error("WebSocket 连接失败")); });
  let nextId = 0;
  const pending = new Map(), listeners = new Map(), problems = [];
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const {resolve, reject} = pending.get(message.id);
      pending.delete(message.id);
      message.error ? reject(new Error(message.error.message)) : resolve(message.result);
    } else if (message.method) {
      (listeners.get(message.method) || []).forEach((handler) => handler(message.params));
      if (message.method === "Runtime.exceptionThrown") problems.push(`异常：${message.params.exceptionDetails.exception?.description || message.params.exceptionDetails.text}`);
      if (message.method === "Runtime.consoleAPICalled" && message.params.type === "error") problems.push(`console.error：${message.params.args.map((arg) => arg.value ?? arg.description).join(" ")}`);
      if (message.method === "Network.loadingFailed" && !message.params.canceled) problems.push(`请求失败：${message.params.errorText}`);
      if (message.method === "Log.entryAdded" && ["error", "warning"].includes(message.params.entry.level)) {
        problems.push(`${message.params.entry.level}：${message.params.entry.text} ${message.params.entry.url || ""}`.trim());
      }
    }
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, {resolve, reject});
    socket.send(JSON.stringify({id, method, params}));
  });
  const once = (method) => new Promise((resolve) => {
    const handler = (params) => { listeners.set(method, listeners.get(method).filter((item) => item !== handler)); resolve(params); };
    listeners.set(method, [...(listeners.get(method) || []), handler]);
  });

  await Promise.all([send("Page.enable"), send("Runtime.enable"), send("Network.enable"), send("Log.enable")]);
  const setViewport = (w, h, s = scale, mobile = false) => send("Emulation.setDeviceMetricsOverride", {width: w, height: h, deviceScaleFactor: s, mobile});
  await setViewport(width, height);

  const page = {
    problems,
    send,
    on: (method, handler) => listeners.set(method, [...(listeners.get(method) || []), handler]),
    setViewport,
    async goto(url) {
      const loaded = once("Page.loadEventFired");
      await send("Page.navigate", {url});
      await loaded;
    },
    // 在页面里执行表达式（可返回 Promise），返回 JSON 值
    async evaluate(expression) {
      const result = await send("Runtime.evaluate", {expression, awaitPromise: true, returnByValue: true});
      if (result.exceptionDetails) throw new Error(`页面脚本出错：${result.exceptionDetails.exception?.description || result.exceptionDetails.text}`);
      return result.result.value;
    },
    async waitFor(expression, {timeout = 20000, interval = 100, label = expression} = {}) {
      const deadline = Date.now() + timeout;
      while (Date.now() < deadline) {
        if (await page.evaluate(`Boolean(${expression})`)) return;
        await sleep(interval);
      }
      throw new Error(`等待超时：${label}`);
    },
    sleep,
    // 截取页面或元素；选择器对应元素的整块区域（含滚动区域之外的部分）
    async screenshot(file, {selector, fullPage = false, padding = 0} = {}) {
      let clip;
      if (selector) {
        const box = await page.evaluate(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); if (!e) return null;
          e.scrollIntoView({block: "start"}); const r = e.getBoundingClientRect(); return {x: r.left + scrollX, y: r.top + scrollY, width: r.width, height: r.height}; })()`);
        if (!box) throw new Error(`截图目标不存在：${selector}`);
        clip = {x: Math.max(0, box.x - padding), y: Math.max(0, box.y - padding), width: box.width + 2 * padding, height: box.height + 2 * padding, scale: 1};
      } else if (fullPage) {
        const size = await page.evaluate("({width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight})");
        clip = {x: 0, y: 0, width: size.width, height: size.height, scale: 1};
      }
      const {data} = await send("Page.captureScreenshot", {format: "png", captureBeyondViewport: true, ...(clip ? {clip} : {})});
      writeFileSync(file, Buffer.from(data, "base64"));
    },
  };

  return {page, async close() {
    try { socket.close(); } catch (error) { /* 已关闭 */ }
    child.kill();
    await sleep(300);
    try { rmSync(profile, {recursive: true, force: true}); } catch (error) { /* Windows 上文件可能仍被占用，留给系统清理 */ }
  }};
}
