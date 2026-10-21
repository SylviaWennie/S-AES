"use strict";

// 页面逻辑：标签页、五关的表单与结果渲染。所有密码运算都在后端完成，这里只组织请求并展示返回的数据。
(() => {
  const {el, hex, bin, groupBits, formatCount, formatMs, formatDuration, parseValue, describeValue, api, getJson, notify,
    download, copyText, guarded} = window.SAES;
  const $ = (id) => document.getElementById(id);
  const hexOfBits = (text) => hex(parseInt(text, 2), Math.ceil(text.length / 4));
  const hexOfInput = (text, width) => { const parsed = parseValue(text, width); return parsed.error ? text.trim() : parsed.value.toString(16).toUpperCase().padStart(width / 4, "0"); };
  const mono = (text, className = "") => el("code", {class: className, text});
  const state = {trace: null, group: null, peers: null, peerIndex: 0, ascii: null, double: null, cbc: null, mitm: null, selftest: {}};
  const TABS = ["basic", "cross", "ascii", "multiple", "cbc", "all"];

  // ------------------------------------------------------------ 公共小部件
  function liveInfo(inputId, infoId, width) {
    const input = $(inputId), info = $(infoId);
    const update = () => {
      const described = describeValue(input.value, width);
      info.textContent = described.error || described.text;
      info.classList.toggle("error", Boolean(described.error));
    };
    input.addEventListener("input", update);
    update();
    return update;
  }

  function fillTable(table, rows, {selectable, onSelect} = {}) {
    const body = table.querySelector("tbody");
    body.replaceChildren(...rows.map((cells, index) => {
      const row = el("tr", selectable ? {"data-selectable": "", tabindex: "0"} : {}, cells.map((item) => (item instanceof Node ? item : el("td", {text: String(item)}))));
      if (selectable) {
        const choose = () => {
          body.querySelectorAll("tr.selected").forEach((other) => other.classList.remove("selected"));
          row.classList.add("selected");
          onSelect(index, row);
        };
        row.addEventListener("click", choose);
        row.addEventListener("keydown", (event) => { if (event.key === "Enter") choose(); });
      }
      return row;
    }));
  }

  const cell = (...children) => el("td", {}, ...children);
  const tick = (ok, text) => el("td", {class: ok ? "ok" : "bad-text", text: text || (ok ? "✓" : "✗")});
  const readoutRow = (name, value) => el("div", {class: "row"}, el("span", {class: "label", text: name}), typeof value === "string" ? mono(value) : value);
  const paddingNote = (ok) => el("p", {class: ok ? "hint" : "check-fail", text: ok ? "填充检查通过。" : "填充无法按所选方式去除：密钥、IV、密文或填充方式可能不匹配，显示的是未去除填充的原始字节。"});

  // 各关第一次显示时才运行默认示例，避免一打开页面就做第 4 关约 3 秒的攻击
  const firstVisit = {};
  const loaders = {};

  function showTab(name, focus = false) {
    TABS.forEach((tab) => {
      const selected = tab === name;
      $(`tab-${tab}`).setAttribute("aria-selected", String(selected));
      $(`tab-${tab}`).tabIndex = selected ? 0 : -1;
      $(`panel-${tab}`).hidden = !selected;
    });
    if (focus) $(`tab-${name}`).focus();
    window.SAESVisuals.pauseAll();
    if (location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
    if (loaders[name] && !firstVisit[name]) { firstVisit[name] = true; loaders[name](); }
  }

  function markPassed(level, passed) {
    const mark = $(`tab-${TABS[level - 1]}`).querySelector(".pass-mark");
    if (mark) mark.hidden = !passed;
  }

  function bindTabs() {
    TABS.forEach((name, index) => {
      $(`tab-${name}`).addEventListener("click", () => showTab(name));
      $(`tab-${name}`).addEventListener("keydown", (event) => {
        const step = {ArrowRight: 1, ArrowLeft: -1}[event.key];
        if (step) { event.preventDefault(); showTab(TABS[(index + step + TABS.length) % TABS.length], true); }
        if (event.key === "Home") { event.preventDefault(); showTab(TABS[0], true); }
        if (event.key === "End") { event.preventDefault(); showTab(TABS[TABS.length - 1], true); }
      });
    });
  }

  // ------------------------------------------------------------ 第 1 关：基本测试
  const EXAMPLES = {
    known: {block: "0110111101101011", key: "1010011100111011", operation: "encrypt"}, // 6F6B / A73B → 0738
    book: {block: "1010011101001001", key: "0010110101010101", operation: "encrypt"},  // A749 / 2D55：依次复现教材 D.2.1–D.2.4 的示例
    zero: {block: "0000000000000000", key: "0000000000000000", operation: "encrypt"},
  };

  function renderBasic(trace) {
    state.trace = trace;
    $("basic-result").textContent = groupBits(bin(trace.result));
    $("basic-result-hex").textContent = hex(trace.result);
    $("basic-result-direction").textContent = trace.mode === "encrypt" ? "密文 · 16 bit" : "明文 · 16 bit";
    trace.round_keys.forEach((key, index) => { $(`basic-k${index}`).textContent = hex(key); });
    const check = trace.roundtrip;
    $("basic-roundtrip").replaceChildren(`${check.operation === "decrypt" ? "解密" : "加密"}回验：${hex(check.input)} → `, el("strong", {text: hex(check.result)}), " ",
      el("span", {class: check.matches ? "check-ok" : "check-fail", text: check.matches ? "✓ 与输入一致" : "✗ 不一致"}));
    $("basic-words").textContent = `w₀…w₅ = ${trace.words.map((word) => hex(word, 2)).join(" ")}`;
  }

  async function runBasic(start = 0) {
    const trace = await api("/api/visual", {operation: $("basic-operation").value, block: $("basic-block").value, key: $("basic-key").value});
    renderBasic(trace);
    window.SAESVisuals.createCipherPlayer($("cipher-visual"), trace, {start});
  }

  function bindBasic() {
    const updateBlock = liveInfo("basic-block", "basic-block-info", 16), updateKey = liveInfo("basic-key", "basic-key-info", 16);
    const setInputs = ({block, key, operation}) => {
      Object.assign($("basic-block"), {value: block});
      Object.assign($("basic-key"), {value: key});
      $("basic-operation").value = operation;
      updateBlock();
      updateKey();
    };
    $("basic-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(() => runBasic(), $("basic-run")); });
    $("basic-use-result").addEventListener("click", () => {
      if (!state.trace) return;
      setInputs({block: bin(state.trace.result), key: $("basic-key").value, operation: state.trace.mode === "encrypt" ? "decrypt" : "encrypt"});
      guarded(() => runBasic(), $("basic-run"));
    });
    $("basic-example").addEventListener("change", (event) => {
      const example = EXAMPLES[event.target.value];
      event.target.value = "";
      if (!example) return;
      setInputs(example);
      guarded(() => runBasic(), $("basic-run"));
    });
    $("basic-operation").addEventListener("change", () => guarded(() => runBasic(), $("basic-run")));
    document.querySelector("#panel-basic details.supplement-details").addEventListener("toggle", (event) => {
      if (!event.target.open || event.target.dataset.loaded) return;
      event.target.dataset.loaded = "1";
      guarded(async () => $("reference-host").replaceChildren(window.SAESFigures.referenceTables(await getJson("/api/spec"))));
    });
    loaders.basic = () => guarded(() => runBasic());
    window.SAESApp = {goBasic(values) {
      Object.assign($("basic-block"), {value: values.block});
      Object.assign($("basic-key"), {value: values.key});
      $("basic-operation").value = values.operation;
      updateBlock();
      updateKey();
      showTab("basic");
      guarded(() => runBasic(5), $("basic-run"));
      $("panel-basic").scrollIntoView({behavior: "smooth", block: "start"});
    }};
  }

  // ------------------------------------------------------------ 第 2 关：交叉测试
  async function runGroup(random) {
    const payload = {key: $("group-key").value};
    if (random) payload.random = 256; else payload.plaintexts = $("group-plaintexts").value;
    const result = await api("/api/group", payload);
    state.group = result;
    window.SAESCharts.statTiles($("group-summary"), [
      {value: `${formatCount(result.counts.encrypt_equal)} / ${formatCount(result.total)}`, label: "A、B、C 加密一致", bad: result.counts.encrypt_equal !== result.total},
      {value: `${formatCount(result.counts.cross_decrypt_ok)} / ${formatCount(result.counts.cross_decrypt_total)}`, label: "3×3 交叉解密还原", bad: result.counts.cross_decrypt_ok !== result.counts.cross_decrypt_total},
      {value: "A · B · C", label: "参与的独立实现"}]);
    $("group-note").textContent = `${result.passed ? "三种实现完全一致。" : "发现不一致，请查看下表。"}${result.rows_shown < result.total ? `表中列出前 ${result.rows_shown} 条，统计覆盖全部 ${formatCount(result.total)} 条。` : ""}${result.notice}`;
    fillTable($("group-table"), result.rows.map((row) => [cell(mono(hexOfBits(row.plaintext))), cell(mono(hexOfBits(row.ciphertexts.A))),
      cell(mono(hexOfBits(row.ciphertexts.B))), cell(mono(hexOfBits(row.ciphertexts.C))), tick(row.equal),
      tick(row.cross.every((item) => item.ok), `${row.cross.filter((item) => item.ok).length}/9`)]),
    {selectable: true, onSelect: (index) => $("group-matrix").replaceChildren(window.SAESFigures.crossMatrix(result.rows[index], result.implementations))});
    $("group-table").querySelector("tbody tr")?.click();
  }

  function peerFrames(row, groups) {
    const make = (sender, receiver, senderTag, receiverTag, cipherBits, decodedBits) => [
      {title: `${senderTag} 组加密`, operation: "encrypt", input: row.plaintext, output: cipherBits, description: `${senderTag} 组用共享密钥加密 16 位明文（${sender.name}）。`},
      {title: `模拟信道 · ${senderTag} → ${receiverTag}`, operation: "transfer", input: cipherBits, output: cipherBits, description: "本地模拟传递密文，没有发送到网络或其他同学。"},
      {title: `${receiverTag} 组解密`, operation: "decrypt", input: cipherBits, output: decodedBits, description: `${receiverTag} 组用自己的实现（${receiver.name}）解密，核对是否等于原明文。`}];
    return {a_to_b: make(groups.a, groups.b, "A", "B", row.a_ciphertext, row.b_decrypted),
      b_to_a: make(groups.b, groups.a, "B", "A", row.b_ciphertext, row.a_decrypted)};
  }

  function showTransfer(index = state.peerIndex) {
    const result = state.peers;
    if (!result) return;
    state.peerIndex = index;
    const row = result.rows[index], groups = {a: result.group_a, b: result.group_b}, direction = $("peer-direction").value;
    const frames = peerFrames(row, groups)[direction];
    const meta = {key: row.key, plaintext: row.plaintext, groups, ciphertext: frames[0].output};
    window.SAESVisuals.createPlayer($("peer-visual"), frames, {duration: 2400, caption: (step) => step.description,
      render: (step, frameIndex) => {
        const scene = window.SAESFigures.transferScene(meta, direction, step, frameIndex);
        return {node: scene.root, frame: scene.frame};
      }});
  }

  async function runPeers() {
    const result = await api("/api/simulate", {key: $("peer-key").value, plaintexts: $("peer-plaintexts").value, group_a: $("peer-a").value, group_b: $("peer-b").value});
    state.peers = result;
    state.peerIndex = 0;
    const total = formatCount(result.total);
    window.SAESCharts.statTiles($("peer-summary"), [
      {value: `${formatCount(result.counts.encrypt_equal)} / ${total}`, label: "A、B 组密文一致", bad: result.counts.encrypt_equal !== result.total},
      {value: `${formatCount(result.counts.a_to_b_ok)} / ${total}`, label: "A → B 解密还原", bad: result.counts.a_to_b_ok !== result.total},
      {value: `${formatCount(result.counts.b_to_a_ok)} / ${total}`, label: "B → A 解密还原", bad: result.counts.b_to_a_ok !== result.total}]);
    $("peer-note").textContent = `A 组：${result.group_a.name}；B 组：${result.group_b.name}。${result.notice}`;
    fillTable($("peer-table"), result.rows.map((row, index) => [cell(mono(hexOfBits(row.plaintext))), cell(mono(hexOfBits(row.a_ciphertext))),
      cell(mono(hexOfBits(row.b_ciphertext))), tick(row.a_to_b_ok && row.b_to_a_ok, `${row.a_to_b_ok ? "✓" : "✗"} / ${row.b_to_a_ok ? "✓" : "✗"}`),
      cell(el("button", {type: "button", text: "回放", on: {click: () => showTransfer(index)}}))]));
    $("peer-download").disabled = false;
    showTransfer(0);
  }

  async function runVerify() {
    let text = $("verify-text").value;
    const file = $("verify-file").files[0];
    if (file && !text.trim()) text = await file.text();
    if (!text.trim()) throw new Error("请选择文件，或粘贴 JSON / 三列文本");
    const payload = {implementation: $("verify-impl").value};
    if (text.trim().startsWith("{")) {
      try { payload.document = JSON.parse(text); } catch (error) { throw new Error("JSON 格式不正确"); }
    } else payload.lines = text;
    const result = await api("/api/verify", payload);
    const bad = result.results.filter((item) => !item.encrypt_ok || !item.decrypt_ok);
    $("verify-result").replaceChildren(
      el("div", {class: "row"}, el("strong", {class: result.passed ? "ok" : "bad-text", text: result.passed ? `全部通过 · 共 ${result.total} 条` : `有 ${bad.length} 条不一致 · 共 ${result.total} 条`})),
      readoutRow("加密一致", `${result.encrypt_passed} / ${result.total}`), readoutRow("解密一致", `${result.decrypt_passed} / ${result.total}`),
      ...result.results.slice(0, 12).map((item) => readoutRow(`#${item.index}`, `${item.encrypt_ok ? "加密 ✓" : "加密 ✗"} / ${item.decrypt_ok ? "解密 ✓" : "解密 ✗"} · 本机 C=${hexOfBits(item.actual_ciphertext)} P=${hexOfBits(item.actual_plaintext)}`)),
      ...(result.total > 12 ? [el("div", {class: "row", text: `… 其余 ${result.total - 12} 条未列出`})] : []));
  }

  function bindCross() {
    $("group-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(() => runGroup(false), $("group-run")); });
    $("group-random").addEventListener("click", () => guarded(() => runGroup(true), $("group-random")));
    $("peer-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(runPeers, $("peer-run")); });
    $("peer-all").addEventListener("click", () => {
      $("peer-plaintexts").value = Array.from({length: 256}, (_, index) => hex(index * 257)).join("\n");
      guarded(runPeers, $("peer-all"));
    });
    $("peer-direction").addEventListener("change", () => showTransfer());
    $("peer-download").addEventListener("click", () => { if (state.peers) download("saes-peer-simulation.json", JSON.stringify(state.peers, null, 2)); });
    const exportDocument = () => api("/api/export", {key: $("export-key").value, plaintexts: $("export-plaintexts").value, implementation: $("export-impl").value});
    $("export-form").addEventListener("submit", (event) => {
      event.preventDefault();
      guarded(async () => download("saes-exchange.json", JSON.stringify(await exportDocument(), null, 2)), $("export-json"));
    });
    $("export-lines").addEventListener("click", () => guarded(async () => {
      const document_ = await exportDocument();
      const text = document_.vectors.map((vector) => `${vector.plaintext_hex} ${vector.key_hex} ${vector.ciphertext_hex}`).join("\n");
      notify(`${await copyText(text) ? "已复制" : "复制失败，请手动选择"} ${document_.vectors.length} 条「明文 密钥 密文」向量，并已填入右侧核验框。`, "info");
      $("verify-text").value = text;
    }));
    $("verify-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(runVerify, $("verify-run")); });
    $("verify-file").addEventListener("change", async (event) => { if (event.target.files[0]) $("verify-text").value = await event.target.files[0].text(); });
    loaders.cross = () => Promise.all([guarded(() => runGroup(false)), guarded(runPeers)]);
  }

  // ------------------------------------------------------------ 第 3 关：扩展功能（字符串）
  function renderAsciiFlow(index) {
    const result = state.ascii;
    if (!result || !result.blocks[index]) return;
    const row = result.blocks[index], encrypting = result.operation === "encrypt";
    const flowRow = encrypting ? row : {...row, plain_block: row.cipher_block, cipher_block: row.plain_block, plain_hex: row.cipher_block, plain_view: row.cipher_view, cipher_view: row.plain_view};
    $("ascii-flow").replaceChildren(window.SAESFigures.asciiFlow(flowRow, hexOfInput($("ascii-key").value, 16), encrypting ? "S-AES 加密" : "S-AES 解密"));
    $("ascii-inspect").disabled = false;
    $("ascii-inspect").dataset.index = String(index);
  }

  async function runAscii() {
    const operation = $("ascii-operation").value;
    const payload = {operation, key: $("ascii-key").value, padding: $("ascii-padding").value, cipher_format: $("ascii-format").value};
    payload[operation === "encrypt" ? "text" : "cipher"] = $("ascii-text").value;
    const result = await api("/api/ascii", payload);
    state.ascii = result;
    if (operation === "encrypt") {
      window.SAESCharts.statTiles($("ascii-summary"), [{value: formatCount(result.plain_bytes), label: "明文字节"}, {value: formatCount(result.padded_bytes), label: "填充后字节"},
        {value: formatCount(result.blocks.length), label: "16 位分组"}]);
      $("ascii-result").replaceChildren(readoutRow("密文（十六进制）", result.cipher_hex), readoutRow("密文（Base64）", result.cipher_base64),
        readoutRow("乱码字符串视图", result.cipher_view), el("p", {class: "hint", text: "密文字节大多不可打印，以 · 代替；传递和解密请使用十六进制或 Base64。"}));
    } else {
      window.SAESCharts.statTiles($("ascii-summary"), [{value: formatCount(result.blocks.length * 2), label: "密文字节"}, {value: formatCount(result.plain_bytes), label: "明文字节"},
        {value: formatCount(result.blocks.length), label: "16 位分组"}]);
      $("ascii-result").replaceChildren(readoutRow("还原的文本", el("span", {text: JSON.stringify(result.text)})), readoutRow("明文字节", result.plain_hex || "（空）"), paddingNote(result.padding_ok));
    }
    fillTable($("ascii-table"), result.blocks.map((row) => [row.index + 1, cell(mono(row.plain_view)), cell(mono(row.plain_hex)), cell(mono(row.plain_block)), cell(mono(row.cipher_block)), cell(mono(row.cipher_view))]),
      {selectable: true, onSelect: renderAsciiFlow});
    $("ascii-table").querySelector("tbody tr")?.click();
  }

  function bindAscii() {
    $("ascii-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(runAscii, $("ascii-run")); });
    $("ascii-refill").addEventListener("click", () => {
      if (!state.ascii || state.ascii.operation !== "encrypt") { notify("请先运行一次加密，再回填密文。", "info"); return; }
      $("ascii-operation").value = "decrypt";
      $("ascii-text").value = $("ascii-format").value === "hex" ? state.ascii.cipher_hex : state.ascii.cipher_base64;
      guarded(runAscii, $("ascii-run"));
    });
    $("ascii-inspect").addEventListener("click", () => {
      const row = state.ascii?.blocks[Number($("ascii-inspect").dataset.index)];
      if (!row) return;
      const encrypting = state.ascii.operation === "encrypt";
      window.SAESApp.goBasic({block: bin(parseInt(encrypting ? row.plain_block : row.cipher_block, 16), 16), key: $("ascii-key").value, operation: encrypting ? "encrypt" : "decrypt"});
    });
    loaders.ascii = () => guarded(runAscii);
  }

  // ------------------------------------------------------------ 第 4 关：多重加密
  const TRIPLE_DEFAULT_KEYS = {ede2: "2D55A73B", ede3: "2D55A73B1C27"};

  async function runDouble() {
    const result = await api("/api/double", {operation: $("double-operation").value, key: $("double-key").value, block: $("double-block").value});
    state.double = result;
    $("double-result").replaceChildren(window.SAESFigures.chainView(result.input, result.steps, result.result),
      el("p", {class: "hint", text: `K1 = ${result.k1.hex}，K2 = ${result.k2.hex}；密钥 ${result.key.hex} 共 32 位。${result.operation === "encrypt" ? "加密先用 K1，再用 K2。" : "解密与加密顺序相反：先用 K2，再用 K1。"}`}));
  }

  async function runTriple() {
    const result = await api("/api/triple", {operation: $("triple-operation").value, mode: $("triple-mode").value, key: $("triple-key").value, block: $("triple-block").value});
    $("triple-result").replaceChildren(window.SAESFigures.chainView(result.input, result.steps, result.result),
      el("p", {class: "hint", text: `子密钥 K1 = ${result.subkeys[0].hex}，K2 = ${result.subkeys[1].hex}，K3 = ${result.subkeys[2].hex}${result.mode === "ede2" ? "（32 位模式下 K3 取 K1）" : ""}。`}));
  }

  function fillMitmExample(example) {
    $("mitm-pairs").value = example.pairs.map((pair) => `${hexOfBits(pair.plaintext)} ${hexOfBits(pair.ciphertext)}`).join("\n");
    $("mitm-secret").value = example.key.hex;
    $("mitm-secret-note").textContent = `示例由密钥 ${example.key.hex} 生成。攻击程序只看明密文对；示例密钥只在攻击结束后用来核对候选集合。`;
  }

  async function runMitm() {
    const result = await api("/api/mitm", {pairs: $("mitm-pairs").value, secret: $("mitm-secret").value});
    state.mitm = result;
    const finalCount = result.counts[result.counts.length - 1];
    window.SAESCharts.statTiles($("mitm-summary"), [
      {value: formatCount(finalCount), label: finalCount === 1 ? "剩余候选密钥（唯一）" : "剩余候选密钥", bad: finalCount === 0},
      {value: formatCount(result.block_operations), label: "分组运算次数"}, {value: formatMs(result.elapsed_ms), label: "实测耗时"},
      {value: `1/${formatCount(Math.round(result.speedup))}`, label: "运算量相对穷举 2³²"}]);
    $("mitm-note").textContent = `穷举 2³² 把密钥约需 ${formatCount(result.exhaustive_operations)} 次加密；按本机单次分组加密 ${result.per_operation_us.toFixed(1)} µs 估算约 ${formatDuration(result.exhaustive_estimate_seconds)}（估算值，不是实测）。建表 ${formatMs(result.table_ms)}。`;
    window.SAESCharts.funnel($("mitm-funnel"), [{label: "全部 K1‖K2", count: 2 ** 32},
      ...result.counts.map((count, index) => ({label: `加入第 ${index + 1} 对后`, count}))], "候选密钥随明密文对数增加而收敛");
    $("mitm-diagram").replaceChildren(window.SAESFigures.mitmDiagram(result));
    const secret = $("mitm-secret").value.trim().toUpperCase();
    $("mitm-secret-check").textContent = result.secret_found === null ? (result.unique ? "已唯一确定密钥" : `${formatCount(result.candidate_total)} 个候选`)
      : result.secret_found ? `示例密钥 ${secret} 在候选中 ✓` : `示例密钥 ${secret} 不在候选中 ✗`;
    fillTable($("mitm-table"), result.candidates.map((item, index) => [index + 1, cell(mono(item.hex)), cell(mono(item.hex.slice(0, 4))), cell(mono(item.hex.slice(4))),
      item.hex === secret ? el("td", {class: "ok", text: "✓ 示例密钥"}) : el("td", {text: result.unique ? "唯一候选" : ""})]));
    $("mitm-candidates").textContent = result.candidate_total > result.listed
      ? `候选共 ${formatCount(result.candidate_total)} 个，仅列出前 ${result.listed} 个。再加入明密文对，候选数会迅速下降。` : `共 ${result.candidate_total} 个候选。`;
  }

  function bindMultiple() {
    $("double-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(runDouble, $("double-run")); });
    $("double-use-result").addEventListener("click", () => {
      if (!state.double) return;
      $("double-block").value = state.double.result.hex;
      $("double-operation").value = state.double.operation === "encrypt" ? "decrypt" : "encrypt";
      guarded(runDouble, $("double-run"));
    });
    $("triple-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(runTriple, $("triple-run")); });
    $("triple-mode").addEventListener("change", () => {
      const mode = $("triple-mode").value;
      $("triple-key").value = TRIPLE_DEFAULT_KEYS[mode];
      $("triple-key-label").textContent = mode === "ede2" ? "32 位密钥 K1‖K2（8 位十六进制）" : "48 位密钥 K1‖K2‖K3（12 位十六进制）";
      $("triple-formula").textContent = mode === "ede2" ? "加密：C = E_K1( D_K2( E_K1( P ) ) )；解密：P = D_K1( E_K2( D_K1( C ) ) )。K3 取 K1。"
        : "加密：C = E_K3( D_K2( E_K1( P ) ) )；解密：P = D_K1( E_K2( D_K3( C ) ) )。";
      guarded(runTriple, $("triple-run"));
    });
    $("mitm-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(runMitm, $("mitm-run")); });
    $("mitm-example").addEventListener("click", () => guarded(async () => { fillMitmExample(await api("/api/mitm/example", {pairs: 3})); await runMitm(); }, $("mitm-example")));
    loaders.multiple = () => Promise.all([guarded(runDouble), guarded(runTriple), guarded(runMitm)]);
  }

  // ------------------------------------------------------------ 第 5 关：CBC
  const randomIv = () => { const values = new Uint16Array(1); crypto.getRandomValues(values); return bin(values[0], 16); };
  const cbcCommon = () => ({key: $("cbc-key").value, iv: $("cbc-iv").value, padding: $("cbc-padding").value});

  async function runCbc() {
    const result = await api("/api/cbc", {operation: "encrypt", ...cbcCommon(), text: $("cbc-text").value});
    state.cbc = result;
    window.SAESCharts.statTiles($("cbc-summary"), [{value: formatCount(result.block_count), label: "16 位分组"}, {value: result.iv.hex, label: "初始向量 IV"},
      {value: `${result.ecb_repeated_blocks} → ${result.cbc_repeated_blocks}`, label: "重复的密文分组（ECB → CBC）"}]);
    $("cbc-package").value = result.package_hex;
    $("cbc-chain").replaceChildren(el("div", {class: "scroll-x"}, window.SAESFigures.cbcChain(result.rows, result.iv.hex)));
    fillTable($("cbc-table"), result.rows.map((row) => [row.index + 1, cell(mono(row.plain)), cell(mono(row.previous)), cell(mono(row.xor_input)), cell(mono(row.cipher))]));
    $("tamper-index").max = String(result.block_count);
    $("tamper-other").max = String(result.block_count);
    $("cbc-decrypt-input").value = result.package_hex;
  }

  async function runCbcDecrypt() {
    const raw = $("cbc-decrypt-input").value.replace(/\s+/g, "");
    let iv = $("cbc-decrypt-iv").value.trim(), cipher = raw;
    if (!iv) { iv = raw.slice(0, 4); cipher = raw.slice(4); }
    const result = await api("/api/cbc", {operation: "decrypt", key: $("cbc-key").value, iv, padding: $("cbc-padding").value, cipher});
    $("cbc-decrypt-result").replaceChildren(readoutRow("使用的 IV", result.iv.hex), readoutRow("还原的文本", el("span", {text: JSON.stringify(result.text)})), paddingNote(result.padding_ok));
  }

  function tamperAction() {
    const type = $("tamper-action").value, action = {type, index: Number($("tamper-index").value) - 1};
    if (type === "replace" || type === "swap") action.other = Number($("tamper-other").value) - 1;
    if (type === "flip") action.bit = Number($("tamper-bit").value);
    if (type === "set") {
      const text = $("tamper-value").value.replace(/\s+/g, "").replace(/^0x/i, "");
      action.value = parseInt(text, text.length === 16 ? 2 : 16);
    }
    return action;
  }

  const textBlocks = (rows, field) => el("div", {class: "text-blocks"}, rows.map((row) => el("span", {class: `tblock status-${row.status}`, text: row[field]})));

  async function runTamper() {
    const result = await api("/api/cbc/tamper", {...cbcCommon(), text: $("cbc-text").value, action: tamperAction()});
    const rows = result.rows.map((row) => ({...row, plain_hex: hexOfBits(row.plain), recovered_hex: hexOfBits(row.recovered)}));
    const number = (row) => `#${row.index + 1}`;
    $("tamper-badge").textContent = result.changed_cipher_blocks.length ? `改动了密文分组 ${result.changed_cipher_blocks.map((value) => `#${value + 1}`).join("、")}` : "密文未发生变化";
    window.SAESCharts.statusStrip($("tamper-strip"), rows);
    $("tamper-text").replaceChildren(el("div", {class: "text-compare"}, el("div", {}, el("span", {class: "label", text: "原文解密"}), textBlocks(rows, "plain_text")),
      el("div", {}, el("span", {class: "label", text: "篡改后解密"}), textBlocks(rows, "recovered_text"))));
    const notes = [];
    if (!result.changed_cipher_blocks.length) notes.push("这次改动没有改变任何密文分组，所以解密结果与原文完全相同。");
    rows.filter((row) => row.status === "garbled").forEach((row) => notes.push(`明文分组 ${number(row)}：对应的密文分组被改动，D(C′) 与原来毫无关系，整块变成乱码（原 ${row.plain_hex} → 现 ${row.recovered_hex}）。`));
    rows.filter((row) => row.status === "bitflip").forEach((row) => notes.push(`明文分组 ${number(row)}：它自己的密文没变，但 Pᵢ = D(Cᵢ) ⊕ Cᵢ₋₁ 用到了被改的前一个分组，所以与原文恰好相差 Cᵢ₋₁ ⊕ C′ᵢ₋₁ = ${hexOfBits(row.xor_difference)}${row.prediction_matches ? "（与预测一致，攻击者可以有意操纵）" : ""}。`));
    if (result.changed_cipher_blocks.length) notes.push(`其余 ${result.summary.intact} 个分组不受影响：CBC 的错误传播只波及被改分组及其后一个分组。`);
    if (result.padding_broken) notes.push("最后一个分组被破坏，填充已无法按所选方式去除，下面显示的是原始字节。");
    $("tamper-notes").replaceChildren(el("ul", {class: "note-list"}, notes.map((text) => el("li", {text}))));
    fillTable($("tamper-table"), rows.map((row) => [row.index + 1, el("td", {}, el("span", {class: `badge ${{intact: "good", bitflip: "warn", garbled: "bad"}[row.status]}`, text: window.SAESCharts.STATUS[row.status].label})),
      cell(mono(hexOfBits(row.cipher))), cell(mono(hexOfBits(row.tampered_cipher))), cell(mono(row.plain_hex)), cell(mono(row.recovered_hex)), cell(mono(hexOfBits(row.xor_difference)))]));
  }

  function syncTamperFields() {
    const type = $("tamper-action").value;
    $("tamper-other-field").hidden = !(type === "replace" || type === "swap");
    $("tamper-bit-field").hidden = type !== "flip";
    $("tamper-value-field").hidden = type !== "set";
  }

  function bindCbc() {
    $("cbc-iv-random").addEventListener("click", () => { $("cbc-iv").value = randomIv(); });
    $("cbc-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(runCbc, $("cbc-run")); });
    $("cbc-copy").addEventListener("click", async () => notify(`${await copyText($("cbc-package").value) ? "已复制" : "复制失败，请手动选择"}传输包。`, "info"));
    $("cbc-to-decrypt").addEventListener("click", () => { $("cbc-decrypt-input").value = $("cbc-package").value; $("cbc-decrypt-form").scrollIntoView({behavior: "smooth"}); });
    $("cbc-decrypt-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(runCbcDecrypt, $("cbc-decrypt-run")); });
    $("tamper-action").addEventListener("change", syncTamperFields);
    $("tamper-form").addEventListener("submit", (event) => { event.preventDefault(); guarded(runTamper, $("tamper-run")); });
    syncTamperFields();
    loaders.cbc = () => guarded(async () => { await runCbc(); await runCbcDecrypt(); await runTamper(); });
  }

  // ------------------------------------------------------------ 一键闯关
  function levelCard(level) {
    const items = level.checks.map((check) => el("li", {}, el("span", {class: `mark ${check.passed ? "ok" : "bad-text"}`, text: check.passed ? "✓" : "✗"}),
      el("span", {text: check.name}), el("span", {class: "ms", text: formatMs(check.ms)}), el("span", {class: "detail", text: check.detail})));
    return el("article", {class: "level-card", dataset: {level: String(level.level), passed: String(level.passed)}},
      el("header", {}, el("h4", {text: `第 ${level.level} 关 · ${level.title}`}),
        el("span", {class: `badge ${level.passed ? "good" : "bad"}`, text: `${level.passed ? "通过" : "未通过"} · ${level.checks.filter((item) => item.passed).length}/${level.checks.length} 项 · ${formatMs(level.elapsed_ms)}`})),
      el("ul", {class: "check-list"}, items));
  }

  async function runAll() {
    const levels = [];
    $("all-levels").replaceChildren();
    $("all-summary").replaceChildren(el("strong", {text: "…/5"}), el("span", {text: "正在运行（第 4 关含中间相遇攻击，约需几秒）"}));
    for (let level = 1; level <= 5; level++) {
      const result = await api("/api/selftest", {level});
      levels.push(result);
      $("all-levels").append(levelCard(result));
      markPassed(level, result.passed);
    }
    const passed = levels.filter((item) => item.passed).length;
    state.selftest = {generated_at: new Date().toISOString(), passed: passed === 5, passed_levels: passed, levels};
    $("all-summary").replaceChildren(el("strong", {text: `${passed}/5`}), el("span", {text: passed === 5 ? "五关全部通过" : "有关卡未通过，请查看下方详情"}));
    $("all-download").disabled = false;
  }

  function bindAll() {
    $("all-run").addEventListener("click", () => guarded(runAll, $("all-run")));
    $("all-download").addEventListener("click", () => download("saes-selftest.json", JSON.stringify(state.selftest, null, 2)));
  }

  // ------------------------------------------------------------ 启动
  bindTabs();
  [bindBasic, bindCross, bindAscii, bindMultiple, bindCbc, bindAll].forEach((bind) => bind());
  const initial = location.hash.slice(1);
  showTab(TABS.includes(initial) ? initial : "basic");
  document.body.dataset.ready = "1";
})();
