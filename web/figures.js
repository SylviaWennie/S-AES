"use strict";

// HTML / SVG 图解：每个变换的计算细节（教材图 D.4 与示例算式）、传输图、计算链、CBC 链、MITM 原理图。
// 所有数字来自后端接口返回的真实运算结果。
window.SAESFigures = (() => {
  const {el, svg, hex, bin, nibbleHex, groupBits, formatCount} = window.SAES;
  const SUB_LABELS = ["S₀,₀", "S₁,₀", "S₀,₁", "S₁,₁"]; // 与 visuals.js 一致：N0..N3 = 按列排列的四个位置
  const PRIME_LABELS = ["S′₀,₀", "S′₁,₀", "S′₀,₁", "S′₁,₁"];
  const nibblesOf = (state) => [state >> 12, (state >> 8) & 15, (state >> 4) & 15, state & 15];
  const spaced = (state) => nibblesOf(state).map(nibbleHex).join(" ");
  const mono = (text, className = "") => el("code", {class: className, text});
  const bits4 = (value) => bin(value, 4);

  // ------------------------------------------------------------ 构件
  // 2×2 状态矩阵（按行显示 [[N0,N2],[N1,N3]]），每格显示十六进制、4 位二进制和位置标记
  function matrixBlock(state, caption, {tone = "data", marks = {}} = {}) {
    const nibbles = nibblesOf(state);
    const cells = [0, 2, 1, 3].map((position) => el("div", {class: `mat-cell ${position < 2 ? "c0" : "c1"} ${marks[position] || ""}`},
      el("span", {class: "mat-tag", text: SUB_LABELS[position]}), el("strong", {text: nibbleHex(nibbles[position])}),
      el("small", {text: bits4(nibbles[position])})));
    return el("figure", {class: "mat-figure"}, el("div", {class: `mat ${tone}`, role: "group", "aria-label": caption}, cells),
      el("figcaption", {text: caption}));
  }

  // 常数矩阵（列混淆的 [[1,4],[4,1]] 等）
  function constantMatrix(values, caption) {
    const cells = values.flat().map((value, index) => el("div", {class: `mat-cell const ${index % 2 === 0 ? "c0" : "c1"}`}, el("strong", {text: nibbleHex(value)})));
    return el("figure", {class: "mat-figure"}, el("div", {class: "mat const-mat", role: "group", "aria-label": caption}, cells), el("figcaption", {text: caption}));
  }

  const operator = (text) => el("span", {class: "mat-op", text});

  function sboxTable(table, lookups) {
    const hits = new Map();
    lookups.forEach((item) => hits.set(item.input, [...(hits.get(item.input) || []), item.position]));
    const header = el("tr", {}, el("th", {class: "corner", text: "i＼j"}), ...[0, 1, 2, 3].map((column) => el("th", {text: bin(column, 2)})));
    const rows = [0, 1, 2, 3].map((row) => el("tr", {}, el("th", {text: bin(row, 2)}), ...[0, 1, 2, 3].map((column) => {
      const index = row * 4 + column, positions = hits.get(index) || [];
      return el("td", {class: positions.length ? `hit hit-${positions[0]}` : ""}, nibbleHex(table[index]),
        positions.length ? el("sup", {text: positions.map((position) => `N${position}`).join(",")}) : null);
    })));
    return el("table", {class: "sbox-table"}, el("thead", {}, header), el("tbody", {}, rows));
  }

  function xorLine(name, value, width = 8) {
    return el("div", {class: "calc-line"}, el("span", {class: "calc-name", text: name}),
      mono(groupBits(bin(value, width)), "calc-bits"), mono(hex(value, width / 4), "calc-hex"));
  }

  // ------------------------------------------------------------ 各变换的计算细节
  function detailStructure(trace, step) {
    const nibbles = nibblesOf(step.block);
    return el("div", {class: "detail-body"},
      el("p", {text: `${step.block_name} ${hex(step.block)} = ${groupBits(bin(step.block))}，按列分成 N0 N1 N2 N3 = ${nibbles.map(nibbleHex).join(" ")}。`}),
      el("div", {class: "mat-row"}, matrixBlock(step.block, "状态矩阵（按列排列）")),
      el("p", {text: `密钥 ${hex(step.key)} = ${groupBits(bin(step.key))}，分成两个 8 位字 w₀ = ${hex(trace.words[0], 2)}，w₁ = ${hex(trace.words[1], 2)}；接下来 4 步扩展出 w₂…w₅，得到轮密钥 K₀ = w₀w₁，K₁ = w₂w₃，K₂ = w₄w₅。`}),
      el("p", {class: "hint", text: "点击左侧整体结构图中的任一方框可以跳到对应步骤。"}));
  }

  function detailKey(trace, step) {
    const g = step.g, w = trace.words;
    const lines = [];
    if (g) {
      const roundIndex = g.round_index;
      lines.push(xorLine(`w${step.target === 2 ? 1 : 3}`, g.input),
        xorLine("RotNib（交换高低半字节）", g.rotated),
        xorLine("SubNib（两个半字节分别查 S 盒）", g.substituted),
        xorLine(`RCON(${roundIndex})`, g.round_constant),
        xorLine(`g(w${step.target === 2 ? 1 : 3}) = SubNib ⊕ RCON`, g.output),
        xorLine(`w${step.target - 2}`, step.left),
        xorLine(`w${step.target} = w${step.target - 2} ⊕ g`, step.result));
    } else {
      lines.push(xorLine(`w${step.target === 3 ? 2 : 4}`, step.left), xorLine(`w${step.target === 3 ? 1 : 3}`, step.right),
        xorLine(`w${step.target} = w${step.target === 3 ? "2 ⊕ w1" : "4 ⊕ w3"}`, step.result));
    }
    const sbox = g ? el("p", {class: "hint", text: `S 盒：${g.lookups.map((item) => `S[${nibbleHex(item.input)}] = ${nibbleHex(item.output)}`).join("，")}。`}) : null;
    return el("div", {class: "detail-body"}, el("div", {class: "calc-grid"}, lines), sbox,
      el("p", {class: "hint", text: `当前已知：${step.known.map((index) => `w${index} = ${hex(w[index], 2)}`).join("，")}。`}));
  }

  function detailAddKey(trace, step) {
    const lines = step.xor.map((item) => el("li", {},
      mono(SUB_LABELS[item.position]), ` ${nibbleHex(item.state)} ⊕ ${nibbleHex(item.key)} = `, el("strong", {text: nibbleHex(item.result)}),
      el("span", {class: "calc-note", text: `（${bits4(item.state)} ⊕ ${bits4(item.key)} = ${bits4(item.result)}）`})));
    return el("div", {class: "detail-body"},
      el("div", {class: "mat-row"}, matrixBlock(step.before, "状态"), operator("⊕"),
        matrixBlock(step.key, `${step.key_name} = ${hex(step.key)}`, {tone: "key"}), operator("="), matrixBlock(step.after, "新状态")),
      el("ul", {class: "calc-list"}, lines),
      el("p", {class: "hint", text: step.key_name === "K0" ? "加密的第 0 轮只有这一步。" : "异或是自身的逆运算：解密时用同一个函数、同一把轮密钥即可还原。"}));
  }

  function detailSubstitute(trace, step) {
    const inverse = step.kind === "inv_substitute";
    const colorOf = {};
    step.lookups.forEach((item) => { colorOf[item.position] = `hit-${item.position}`; });
    const lines = step.lookups.map((item) => el("li", {},
      el("span", {class: `chip hit-${item.position}`, text: `N${item.position}`}),
      mono(` ${nibbleHex(item.input)} = ${bits4(item.input)}`), ` → 行 ${bin(item.row, 2)} · 列 ${bin(item.column, 2)} → `,
      el("strong", {text: nibbleHex(item.output)}), el("span", {class: "calc-note", text: `（${bits4(item.output)}）`})));
    return el("div", {class: "detail-body"},
      el("div", {class: "mat-row"}, matrixBlock(step.before, "状态", {marks: colorOf}), operator(inverse ? "S⁻¹ →" : "S →"), matrixBlock(step.after, "新状态", {marks: colorOf})),
      el("div", {class: "sbox-wrap"}, sboxTable(step.table, step.lookups),
        el("div", {}, el("p", {class: "hint", text: inverse ? "逆 S 盒（表 D.1(b)）：左 2 位选行、右 2 位选列。" : "S 盒（表 D.1(a)）：左 2 位选行、右 2 位选列。"}),
          el("ul", {class: "calc-list"}, lines))));
  }

  function detailShift(trace, step) {
    return el("div", {class: "detail-body"},
      el("div", {class: "mat-row"}, matrixBlock(step.before, "状态"), operator(step.kind === "shift_rows" ? "SR →" : "ISR →"), matrixBlock(step.after, "新状态")),
      el("p", {text: `第一行（S₀,₀ ${nibbleHex(nibblesOf(step.before)[0])}、S₀,₁ ${nibbleHex(nibblesOf(step.before)[2])}）不变；第二行的两个半字节互换：`
        + `S₁,₀ ${nibbleHex(nibblesOf(step.before)[1])} ↔ S₁,₁ ${nibbleHex(nibblesOf(step.before)[3])}。`}),
      el("p", {class: "hint", text: "只有两个半字节，循环移一个半字节就是互换，因此逆行移位与行移位完全相同。"}));
  }

  function detailMix(trace, step) {
    const inverse = step.kind === "inv_mix_columns";
    const lines = step.terms.map((term) => {
      const [first, second] = term.parts;
      const notes = term.parts.filter((part) => part.coefficient !== 1 && part.value > 1).map((part) =>
        el("div", {class: "poly", text: `${nibbleHex(part.coefficient)}·${nibbleHex(part.value)}：${part.text} = ${nibbleHex(part.product)}`}));
      return el("li", {},
        mono(PRIME_LABELS[term.position]), ` = ${nibbleHex(first.coefficient)}·${nibbleHex(first.value)} ⊕ ${nibbleHex(second.coefficient)}·${nibbleHex(second.value)}`
        + ` = ${nibbleHex(first.product)} ⊕ ${nibbleHex(second.product)} = `, el("strong", {text: nibbleHex(term.result)}), notes);
    });
    return el("div", {class: "detail-body"},
      el("div", {class: "mat-row"}, constantMatrix(step.matrix, inverse ? "M⁻¹" : "M"), operator("×"), matrixBlock(step.before, "状态"), operator("="), matrixBlock(step.after, "新状态")),
      el("ul", {class: "calc-list"}, lines),
      el("p", {class: "hint", text: "加法是异或，乘法在 GF(2⁴) 上进行（模 x⁴+x+1）。例如教材附件 D.1：4·C = x²·(x³+x²) = x⁵+x⁴ ≡ x²+1 = 5。"}));
  }

  const DETAIL_BUILDERS = {structure: detailStructure, key_expansion: detailKey, add_key: detailAddKey, substitute: detailSubstitute,
    inv_substitute: detailSubstitute, shift_rows: detailShift, inv_shift_rows: detailShift, mix_columns: detailMix, inv_mix_columns: detailMix};

  function stepDetail(trace, step) {
    const heading = step.phase === "cipher" ? `${step.label} ${step.name} · 计算细节（图 D.4）`
      : step.phase === "key" ? "密钥扩展 · 计算细节" : "数据结构说明";
    return el("div", {class: `viz-detail kind-${step.kind}`}, el("h4", {class: "viz-detail-title", text: heading}),
      DETAIL_BUILDERS[step.kind](trace, step));
  }

  // ------------------------------------------------------------ 原理速查表
  function referenceTables(spec) {
    const sbox = (title, table) => el("figure", {class: "ref-figure"}, sboxTable(table, []), el("figcaption", {text: title}));
    const multiplication = el("table", {class: "mult-table"},
      el("thead", {}, el("tr", {}, el("th", {text: "×"}), ...Array.from({length: 16}, (_, value) => el("th", {text: nibbleHex(value)})))),
      el("tbody", {}, spec.multiplication.map((row, a) => el("tr", {}, el("th", {text: nibbleHex(a)}),
        ...row.map((value, b) => el("td", {class: [1, 2, 4, 9].includes(a) || [1, 2, 4, 9].includes(b) ? "emph" : "", text: nibbleHex(value)}))))));
    return el("div", {class: "ref-grid"},
      sbox("表 D.1(a) S 盒", spec.sbox), sbox("表 D.1(b) 逆 S 盒", spec.inv_sbox),
      el("div", {class: "ref-facts"},
        el("p", {}, "列混淆矩阵 ", mono(JSON.stringify(spec.mix_matrix).replaceAll(",", ", ")), "，逆矩阵 ", mono(JSON.stringify(spec.inv_mix_matrix).replaceAll(",", ", "))),
        el("p", {}, "模多项式 ", mono(`x⁴+x+1 = 0b${bin(spec.modulus, 5)}`), "；轮常数 RCON(1) = ", mono(hex(spec.round_constants[0], 2)), "，RCON(2) = ", mono(hex(spec.round_constants[1], 2))),
        el("p", {}, "算法标识 ", mono(spec.spec_id), "（交换文件用它核对双方的约定是否一致）"),
        el("p", {class: "hint", text: "下表是 GF(2⁴) 乘法表（表 D.2(b)），加法就是按位异或。列混淆只用到系数 1、2、4、9。"})),
      el("div", {class: "ref-wide"}, multiplication));
  }

  // ------------------------------------------------------------ 计算链（双重 / 三重加密）
  function chainView(input, steps, result) {
    const value = (title, item, kind) => el("div", {class: `chain-node value ${kind}`}, el("span", {text: title}), el("strong", {text: item.hex}), el("small", {text: item.grouped}));
    const nodes = [value("输入", input, "start")];
    steps.forEach((step, index) => {
      nodes.push(el("span", {class: "chain-arrow", text: "→"}),
        el("div", {class: "chain-node op"}, el("strong", {text: step.name}), el("small", {text: `密钥 ${step.key.hex}`})),
        el("span", {class: "chain-arrow", text: "→"}),
        index === steps.length - 1 ? value("输出", result, "end") : value(`中间值 ${index + 1}`, step.output, "mid"));
    });
    return el("div", {class: "chain", role: "group", "aria-label": "多重加密的计算链"}, nodes);
  }

  // ------------------------------------------------------------ 字符串分组流程
  function asciiFlow(row, key, cipherName) {
    const node = (title, value, note, kind = "") => el("div", {class: `chain-node value ${kind}`}, el("span", {text: title}), el("strong", {text: value}), note ? el("small", {text: note}) : null);
    const plainBits = groupBits(bin(parseInt(row.plain_block, 16), 16));
    const cipherBits = groupBits(bin(parseInt(row.cipher_block, 16), 16));
    return el("div", {class: "chain", role: "group", "aria-label": `第 ${row.index + 1} 个分组的转换路径`},
      node("明文字符", JSON.stringify(row.plain_view).slice(1, -1), "2 个字节"),
      el("span", {class: "chain-arrow", text: "→"}), node("字节（十六进制）", row.plain_hex.replace(/(..)/g, "$1 ").trim(), "高字节在前"),
      el("span", {class: "chain-arrow", text: "→"}), node("16 位分组", row.plain_block, plainBits),
      el("span", {class: "chain-arrow", text: "→"}), el("div", {class: "chain-node op"}, el("strong", {text: cipherName}), el("small", {text: `密钥 ${key}`})),
      el("span", {class: "chain-arrow", text: "→"}), node("密文分组", row.cipher_block, cipherBits, "end"),
      el("span", {class: "chain-arrow", text: "→"}), node("密文字节", row.cipher_block.replace(/(..)/g, "$1 ").trim(), `显示为 ${row.cipher_view}`));
  }

  // ------------------------------------------------------------ 组内 3×3 交叉解密矩阵
  function crossMatrix(row, implementations) {
    const names = implementations.map((item) => item.key);
    const lookup = Object.fromEntries(row.cross.map((cell) => [`${cell.from}${cell.to}`, cell.ok]));
    return el("div", {},
      el("p", {class: "hint", text: `明文 ${hex(parseInt(row.plaintext, 2))}：行是“谁来加密”，列是“谁来解密”，✓ 表示还原出原明文。`}),
      el("table", {class: "data-table cross-matrix"}, el("thead", {}, el("tr", {}, el("th", {text: "加密 ＼ 解密"}),
        ...names.map((name) => el("th", {text: `实现 ${name}`})), el("th", {text: "该实现的密文"}))),
        el("tbody", {}, names.map((from) => el("tr", {}, el("th", {text: `实现 ${from}`}),
          ...names.map((to) => el("td", {class: lookup[`${from}${to}`] ? "ok" : "bad-text", text: lookup[`${from}${to}`] ? "✓" : "✗"})),
          el("td", {}, mono(hex(parseInt(row.ciphertexts[from], 2)))))))));
  }

  // ------------------------------------------------------------ 组间传输图（可放入播放器）
  // meta = {key, plaintext, ciphertext, groups: {a, b}}（均为后端返回的位串或名称）；index：0 加密、1 传递、2 解密
  function transferScene(meta, direction, step, index) {
    const V = window.SAESVisuals;
    const {root, arrow} = V.makeSvg(560, 270, "两个小组之间的加密、传递与解密");
    const forward = direction === "a_to_b";
    const sender = forward ? meta.groups.a : meta.groups.b, receiver = forward ? meta.groups.b : meta.groups.a;
    const hexOf = (bitsText) => hex(parseInt(bitsText, 2));
    V.label(root, 280, 24, `双方共享密钥 K = ${hexOf(meta.key)}`, "viz-figure-title");
    const side = (x, title, subtitle, lines, active) => {
      const group = V.add(root, svg("g", {class: `viz-peer ${active ? "is-active" : ""}`}));
      group.append(svg("rect", {x, y: 52, width: 210, height: 150, rx: 12}));
      V.label(group, x + 105, 82, title, "viz-box-title");
      V.label(group, x + 105, 104, subtitle, "viz-caption-text");
      lines.forEach((line, order) => V.label(group, x + 105, 142 + order * 28, line, order === 0 ? "viz-box-value" : "viz-caption-text"));
    };
    side(24, `${forward ? "A" : "B"} 组`, sender.name, [index === 0 ? `${hexOf(step.input)} → ${hexOf(step.output)}` : `密文 ${hexOf(meta.ciphertext)}`, index === 0 ? "加密" : "已发送"], index === 0);
    side(326, `${forward ? "B" : "A"} 组`, receiver.name, [index === 2 ? `${hexOf(step.input)} → ${hexOf(step.output)}` : "等待接收", index === 2 ? "解密" : "密文未到达"], index === 2);
    V.path(root, "M 240 127 H 322", "viz-wire viz-channel", {"marker-end": arrow});
    V.label(root, 281, 96, "本地模拟信道", "viz-caption-text");
    const packet = V.add(root, svg("g", {class: "viz-packet"}, svg("rect", {x: -30, y: -14, width: 60, height: 28, rx: 7}),
      svg("text", {x: 0, y: 5, "text-anchor": "middle", text: hexOf(meta.ciphertext)})));
    const restored = index === 2 && hexOf(step.output) === hexOf(meta.plaintext);
    V.label(root, 280, 238, index === 2 ? `对照发送前的明文 ${hexOf(meta.plaintext)}：${restored ? "还原一致 ✓" : "不一致 ✗"}`
      : index === 1 ? "只传递密文，双方事先约定同一把密钥" : "各自调用自己的实现，结果由后端实际计算", "viz-text");
    V.label(root, 280, 258, "个人在同一台机器上模拟两个小组，没有外部小组或真实网络通信。", "viz-caption-text");
    const frame = (progress, animated) => {
      const fraction = animated ? progress : 0.5;
      packet.setAttribute("transform", `translate(${236 + fraction * 90} 127)`);
      packet.classList.toggle("is-hidden", index !== 1);
    };
    return {root, frame};
  }

  // ------------------------------------------------------------ CBC 链
  function cbcChain(rows, ivHex, limit = 8) {
    const V = window.SAESVisuals;
    const shown = rows.slice(0, limit);
    const width = 150 + shown.length * 128, height = 262;
    const {root, arrow} = V.makeSvg(width, height, "CBC 加密链：每个明文分组先与前一个密文分组异或，再加密");
    const centerX = (index) => 130 + index * 128 + 64;
    V.pill(root, 60, 230, 88, 44, "IV = C₀", ivHex, "viz-key is-done");
    shown.forEach((row, index) => {
      const x = centerX(index);
      V.pill(root, x, 40, 88, 44, `明文 P${index + 1}`, row.plain, "viz-terminal");
      V.path(root, `M ${x} 62 V 92`, "viz-wire", {"marker-end": arrow});
      V.circleXor(root, x, 104, 12);
      V.path(root, `M ${x} 116 V 142`, "viz-wire", {"marker-end": arrow});
      V.pill(root, x, 164, 88, 44, "E_K", "加密", "viz-op is-done");
      V.path(root, `M ${x} 186 V 208`, "viz-wire", {"marker-end": arrow});
      V.pill(root, x, 230, 88, 44, `密文 C${index + 1}`, row.cipher, "viz-terminal is-done");
      const previousX = index === 0 ? 60 : centerX(index - 1);
      V.path(root, `M ${previousX + 44} 230 H ${x - 56} V 104 H ${x - 14}`, "viz-wire viz-wire-key", {"marker-end": arrow});
    });
    if (rows.length > limit) V.label(root, width - 36, 130, `… 共 ${rows.length} 个`, "viz-caption-text");
    return root;
  }

  // ------------------------------------------------------------ 中间相遇攻击原理图
  function mitmDiagram(result) {
    const V = window.SAESVisuals;
    const {root, arrow} = V.makeSvg(600, 250, "中间相遇攻击：从两端分别计算，在中间值处相遇");
    const first = result.pairs[0];
    const hexOf = (bitsText) => hex(parseInt(bitsText, 2));
    const entries = `${formatCount(result.table_entries)} 次`;
    V.label(root, 300, 20, "总计约 2×2¹⁶ 次分组运算，而不是 2³²", "viz-figure-title");
    V.pill(root, 62, 84, 100, 44, "明文 P", hexOf(first.plaintext), "viz-terminal");
    V.pill(root, 62, 204, 100, 44, "密文 C", hexOf(first.ciphertext), "viz-terminal");
    V.pill(root, 212, 84, 150, 44, "枚举 K1：E_K1(P)", entries, "viz-op is-done");
    V.pill(root, 212, 204, 150, 44, "枚举 K2：D_K2(C)", entries, "viz-op is-done");
    V.pill(root, 500, 144, 170, 64, "中间值表 M → K1", `${formatCount(result.table_entries)} 项`, "viz-key is-done");
    V.path(root, "M 112 84 H 137", "viz-wire", {"marker-end": arrow});
    V.path(root, "M 112 204 H 137", "viz-wire", {"marker-end": arrow});
    V.path(root, "M 287 84 H 340 V 128 H 415", "viz-wire", {"marker-end": arrow});
    V.path(root, "M 287 204 H 340 V 160 H 415", "viz-wire", {"marker-end": arrow});
    V.label(root, 296, 62, "存入：M = E_K1(P)，记下 K1", "viz-caption-text", "start");
    V.label(root, 296, 232, "查表：D_K2(C) 命中 → 候选 (K1, K2)", "viz-caption-text", "start");
    V.label(root, 500, 196, `第 1 对后候选 ${formatCount(result.counts[0])} 个`, "viz-caption-text");
    return root;
  }

  return {stepDetail, referenceTables, chainView, asciiFlow, crossMatrix, transferScene, cbcChain, mitmDiagram, matrixBlock, spaced};
})();
