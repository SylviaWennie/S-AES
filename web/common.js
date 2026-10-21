"use strict";

// 公共工具：DOM / SVG 构造、数值格式化、接口调用与提示。
// 用户输入只通过 textContent 进入页面，不拼接 HTML。
window.SAES = (() => {
  const SVG_NS = "http://www.w3.org/2000/svg";

  function appendChildren(parent, children) {
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
  }

  function el(tag, attributes = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attributes)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key === "dataset") Object.assign(node.dataset, value);
      else if (key === "on") for (const [type, handler] of Object.entries(value)) node.addEventListener(type, handler);
      else node.setAttribute(key, value === true ? "" : value);
    }
    appendChildren(node, children);
    return node;
  }

  function svg(tag, attributes = {}, ...children) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [key, value] of Object.entries(attributes)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "text") node.textContent = value;
      else node.setAttribute(key, value);
    }
    appendChildren(node, children);
    return node;
  }

  const hex = (value, digits = 4) => value.toString(16).toUpperCase().padStart(digits, "0");
  const bin = (value, width = 16) => value.toString(2).padStart(width, "0");
  const groupBits = (text) => text.replace(/(.{4})(?=.)/g, "$1 ");
  const nibbleHex = (value) => value.toString(16).toUpperCase();
  const formatCount = (value) => Number(value).toLocaleString("en-US");

  function formatMs(milliseconds) {
    if (milliseconds >= 1000) return `${(milliseconds / 1000).toFixed(2)} s`;
    return `${milliseconds < 10 ? milliseconds.toFixed(2) : Math.round(milliseconds)} ms`;
  }

  function formatDuration(seconds) {
    if (seconds >= 86400) return `${(seconds / 86400).toFixed(1)} 天`;
    if (seconds >= 3600) return `${(seconds / 3600).toFixed(1)} 小时`;
    if (seconds >= 60) return `${(seconds / 60).toFixed(1)} 分钟`;
    return `${seconds.toFixed(1)} 秒`;
  }

  // 与 saes.formats.parse_value 保持一致的前端预检，只用于即时提示，真正的校验仍由后端完成
  function parseValue(text, width) {
    const compact = String(text).replace(/\s+/g, "");
    if (compact.length === width && /^[01]+$/.test(compact)) return {value: BigInt("0b" + compact), kind: "二进制"};
    const stripped = compact.replace(/^0x/i, "");
    if (stripped.length === width / 4 && /^[0-9a-f]+$/i.test(stripped)) return {value: BigInt("0x" + stripped), kind: "十六进制"};
    return {error: `需要 ${width} 位二进制或 ${width / 4} 位十六进制，当前 ${compact.length} 个字符`};
  }

  function describeValue(text, width) {
    const parsed = parseValue(text, width);
    if (parsed.error) return {error: parsed.error};
    const digits = width / 4;
    const hexText = parsed.value.toString(16).toUpperCase().padStart(digits, "0");
    const binText = parsed.value.toString(2).padStart(width, "0");
    return {text: `${parsed.kind} → 0x${hexText} · ${groupBits(binText)}`};
  }

  async function request(path, options) {
    let response;
    try {
      response = await fetch(path, options);
    } catch (error) {
      throw new Error("无法连接本地服务：请确认已在终端运行 python app.py，且浏览器地址与端口一致。");
    }
    let body = null;
    try {
      body = await response.json();
    } catch (error) {
      throw new Error("服务返回了无法解析的内容");
    }
    if (!response.ok) throw new Error(body && body.error ? body.error : "请求失败");
    return body;
  }

  const api = (path, payload) => request(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)});
  const getJson = (path) => request(path, {method: "GET"});

  function notify(message, kind = "error") {
    const box = document.getElementById("notice");
    box.textContent = message;
    box.className = kind === "info" ? "notice info" : "notice";
    box.hidden = false;
  }

  function clearNotice() {
    document.getElementById("notice").hidden = true;
  }

  function download(filename, content, mime = "application/json") {
    const link = el("a", {href: URL.createObjectURL(new Blob([content], {type: `${mime};charset=utf-8`})), download: filename});
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      const area = el("textarea", {"aria-hidden": "true"});
      area.style.position = "fixed";
      area.style.opacity = "0";
      area.value = text;
      document.body.append(area);
      area.select();
      const done = document.execCommand("copy");
      area.remove();
      return done;
    }
  }

  // 运行异步动作并在出错时给出提示；避免每个按钮重复 try / catch
  async function guarded(action, button) {
    if (button) button.disabled = true;
    try {
      clearNotice();
      return await action();
    } catch (error) {
      notify(error.message);
      return null;
    } finally {
      if (button) button.disabled = false;
    }
  }

  function lines(text) {
    return String(text).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  }

  return {el, svg, hex, bin, groupBits, nibbleHex, formatCount, formatMs, formatDuration, parseValue, describeValue,
    api, getJson, notify, clearNotice, download, copyText, guarded, lines};
})();
