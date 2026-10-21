"use strict";

// SVG 图解：只绘制后端已经算好的真实中间值，页面里不维护第二套密码算法。
// 对应教材附录 D：图 D.1 整体结构、图 D.2 数据结构、图 D.3 轮函数、图 D.5 密钥扩展。
window.SAESVisuals = (() => {
  const {el, svg, hex, bin, nibbleHex} = window.SAES;
  const players = new Set();
  let serial = 0;

  const CELL_W = 50, CELL_H = 40, CELL_GAP = 4;
  const SUB_LABELS = ["S₀,₀", "S₁,₀", "S₀,₁", "S₁,₁"]; // 状态矩阵按列排列：N0..N3 依次对应这四个位置
  const nibblesOf = (state) => [state >> 12, (state >> 8) & 15, (state >> 4) & 15, state & 15];
  const spaced = (state) => nibblesOf(state).map(nibbleHex).join(" ");
  const motionReduced = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const toggle = (node, className, enabled) => node.classList.toggle(className, Boolean(enabled));

  // ------------------------------------------------------------ 基础图元
  function makeSvg(width, height, label) {
    const id = `saes-arrow-${++serial}`;
    const marker = svg("marker", {id, viewBox: "0 0 10 10", refX: 8.5, refY: 5, markerWidth: 6.5, markerHeight: 6.5, orient: "auto-start-reverse"},
      svg("path", {d: "M 0 0 L 10 5 L 0 10 z", fill: "context-stroke"}));
    const root = svg("svg", {viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": label, class: "viz-diagram"},
      svg("title", {text: label}), svg("defs", {}, marker));
    return {root, arrow: `url(#${id})`};
  }

  const add = (parent, node) => { parent.append(node); return node; };
  const label = (parent, x, y, content, className = "viz-text", anchor = "middle") =>
    add(parent, svg("text", {x, y, class: className, "text-anchor": anchor, text: content}));
  const path = (parent, d, className, extra = {}) => add(parent, svg("path", {d, fill: "none", class: className, ...extra}));
  const rect = (parent, x, y, width, height, className, radius = 6) =>
    add(parent, svg("rect", {x, y, width, height, rx: radius, class: className}));

  function circleXor(parent, cx, cy, radius = 11) {
    return add(parent, svg("g", {class: "viz-xor"},
      svg("circle", {cx, cy, r: radius}),
      svg("path", {d: `M ${cx - radius + 3} ${cy} H ${cx + radius - 3} M ${cx} ${cy - radius + 3} V ${cy + radius - 3}`})));
  }

  // 带标题和数值的圆角框；传入 onClick 时可点击、可键盘操作
  function pill(parent, cx, cy, width, height, title, value, className = "viz-terminal", onClick) {
    const group = add(parent, svg("g", {class: `viz-box ${className}`}));
    group.append(svg("rect", {x: cx - width / 2, y: cy - height / 2, width, height, rx: 10}));
    label(group, cx, cy - 5, title, "viz-box-title");
    label(group, cx, cy + 14, value, "viz-box-value");
    if (onClick) {
      group.setAttribute("tabindex", "0");
      group.setAttribute("role", "button");
      group.setAttribute("aria-label", `${title}：${value}`);
      group.addEventListener("click", onClick);
      group.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onClick(); }
      });
    }
    return group;
  }

  // 状态列：4 个半字节自上而下依次是 S0,0 S1,0 S0,1 S1,1（图 D.3）；前两格是第 0 列，用深色，后两格用浅色
  function stateColumn(parent, x, top, nibbles) {
    return nibbles.map((value, index) => {
      const y = top + index * (CELL_H + CELL_GAP);
      return add(parent, svg("g", {class: "viz-cell-group"},
        svg("rect", {x, y, width: CELL_W, height: CELL_H, rx: 4, class: `viz-cell ${index < 2 ? "c0" : "c1"}`}),
        svg("text", {x: x + 4, y: y + 11, class: "viz-cell-tag", text: SUB_LABELS[index]}),
        svg("text", {x: x + CELL_W / 2, y: y + 29, class: "viz-cell-value", "text-anchor": "middle", text: nibbleHex(value)}),
        svg("text", {x: x + CELL_W / 2, y: y + 29, class: "viz-cell-q", "text-anchor": "middle", text: "?"})));
    });
  }

  // 带名字的字（w0…w5）方框
  function wordBox(parent, x, y, name, value, known, active, width = 52, height = 40, valueOffset = 11) {
    return add(parent, svg("g", {class: `viz-word ${known ? "" : "pending"} ${active ? "is-active" : ""}`},
      svg("rect", {x, y, width, height, rx: 6}),
      svg("text", {x: x + 5, y: y + 11, class: "viz-cell-tag", text: name}),
      svg("text", {x: x + width / 2, y: y + height - valueOffset, class: "viz-cell-value", "text-anchor": "middle", text: value}),
      svg("text", {x: x + width / 2, y: y + height - valueOffset, class: "viz-cell-q", "text-anchor": "middle", text: "?"})));
  }

  // ------------------------------------------------------------ 图 D.3：轮函数
  // 一个「轮」由若干变换串联：n 个变换对应 n+1 列状态。当前步骤之前的变换已完成，之后的变换尚未发生。
  function drawRound(trace, step) {
    const groupSteps = trace.steps.filter((item) => item.phase === "cipher" && item.group === step.group);
    const count = groupSteps.length;
    const position = groupSteps.indexOf(step);
    const width = 560, height = 280, margin = 14, top = 70;
    const gap = (width - 2 * margin - (count + 1) * CELL_W) / count;
    const columnX = (index) => margin + index * (CELL_W + gap);
    const rowY = (index) => top + index * (CELL_H + CELL_GAP) + CELL_H / 2;
    const {root, arrow} = makeSvg(width, height, `${step.title}：轮函数图（教材图 D.3）`);

    const columns = [];
    for (let index = 0; index <= count; index++) {
      columns.push(stateColumn(root, columnX(index), top, nibblesOf(index === 0 ? groupSteps[0].before : groupSteps[index - 1].after)));
      label(root, columnX(index) + CELL_W / 2, top + 4 * (CELL_H + CELL_GAP) + 12, "状态", "viz-caption-text");
    }

    const stages = groupSteps.map((item, index) => {
      const left = columnX(index) + CELL_W, right = columnX(index + 1), middle = (left + right) / 2;
      const nodes = [], marks = [];
      const wire = (d, className = "viz-wire") => { const node = path(root, d, className, {"marker-end": arrow}); nodes.push(node); return node; };
      nodes.push(label(root, middle, 26, item.kind === "add_key" ? `${item.label} 轮密钥加` : `${item.label} ${item.name}`, "viz-stage-title"));
      if (item.kind === "add_key") nodes.push(label(root, middle, 44, `${item.key_name} = ${hex(item.key)}`, "viz-key-text"));

      if (item.kind === "substitute" || item.kind === "inv_substitute") {
        for (let row = 0; row < 4; row++) {
          const y = rowY(row);
          wire(`M ${left} ${y} H ${middle - 15}`);
          const box = add(root, svg("g", {class: "viz-sbox"}, svg("rect", {x: middle - 14, y: y - 14, width: 28, height: 28, rx: 5}),
            svg("text", {x: middle, y: y + 5, "text-anchor": "middle", text: item.kind === "substitute" ? "S" : "S⁻¹"})));
          marks.push(box);
          wire(`M ${middle + 15} ${y} H ${right}`);
        }
      } else if (item.kind === "shift_rows" || item.kind === "inv_shift_rows") {
        item.mapping.forEach((source, outputRow) => wire(`M ${left} ${rowY(source)} L ${right} ${rowY(outputRow)}`));
        nodes.push(label(root, middle, rowY(3) + 32, "第二行互换", "viz-caption-text"));
      } else if (item.kind === "mix_columns" || item.kind === "inv_mix_columns") {
        for (let column = 0; column < 2; column++) {
          const upper = rowY(2 * column), lower = rowY(2 * column + 1);
          const boxTop = upper - 14, boxHeight = lower - upper + 28;
          wire(`M ${left} ${upper} L ${middle - 17} ${upper + 10}`);
          wire(`M ${left} ${lower} L ${middle - 17} ${lower - 10}`);
          marks.push(add(root, svg("g", {class: "viz-mbox"}, svg("rect", {x: middle - 16, y: boxTop, width: 32, height: boxHeight, rx: 6}),
            svg("text", {x: middle, y: boxTop + boxHeight / 2 + 5, "text-anchor": "middle", text: item.kind === "mix_columns" ? "M" : "M⁻¹"}))));
          wire(`M ${middle + 17} ${upper + 10} L ${right} ${upper}`);
          wire(`M ${middle + 17} ${lower - 10} L ${right} ${lower}`);
        }
      } else {
        item.xor.forEach((entry, row) => {
          const y = rowY(row);
          wire(`M ${left} ${y} H ${middle - 12}`);
          marks.push(circleXor(root, middle, y));
          wire(`M ${middle + 12} ${y} H ${right}`);
          nodes.push(add(root, svg("g", {class: "viz-keycell"}, svg("rect", {x: middle - 21, y: y - 34, width: 42, height: 16, rx: 4}),
            svg("text", {x: middle, y: y - 22, "text-anchor": "middle", text: `r${row} = ${nibbleHex(entry.key)}`}))));
          wire(`M ${middle} ${y - 18} V ${y - 13}`, "viz-wire viz-wire-key");
        });
      }
      return {index, nodes: [...nodes, ...marks], marks};
    });

    function frame(progress, animated) {
      const fullyShown = !animated || progress >= 1;
      stages.forEach((stage) => {
        const state = stage.index < position ? "done" : stage.index === position ? "active" : "future";
        stage.nodes.forEach((node) => {
          toggle(node, "is-active", state === "active");
          toggle(node, "is-future", state === "future");
        });
        stage.marks.forEach((mark, order) =>
          toggle(mark, "is-lit", state === "active" && animated && progress < 1 && progress > order / stage.marks.length * 0.8));
      });
      columns.forEach((cells, index) => cells.forEach((cell, row) => {
        const shown = index <= position || (index === position + 1 && (fullyShown || progress >= 0.25 + row * 0.18));
        toggle(cell, "pending", !shown);
        toggle(cell, "is-result", index === position + 1 && shown);
      }));
    }
    return {root, frame};
  }

  // ------------------------------------------------------------ 图 D.5：密钥扩展
  function drawKeyExpansion(trace, step) {
    const {root, arrow} = makeSvg(560, 424, "S-AES 密钥扩展（教材图 D.5）");
    const known = new Set(step.known), target = step.target, words = trace.words;
    const word = (x, y, index) => wordBox(root, x, y, `w${index}`, hex(words[index], 2), known.has(index), index === target);
    // 连线与节点都标注它服务于哪个输出字；当前目标高亮，尚未算到的目标变淡
    const tag = (node, targets) => {
      toggle(node, "is-active", targets.includes(target));
      toggle(node, "is-future", targets.every((value) => value > target));
      return node;
    };
    const wire = (d, targets) => tag(path(root, d, "viz-wire", {"marker-end": arrow}), targets);
    const gCircle = (cx, cy, targets) => tag(add(root, svg("g", {class: "viz-gcircle"}, svg("circle", {cx, cy, r: 15}),
      svg("text", {x: cx, y: cy + 5, "text-anchor": "middle", text: "g"}))), targets);

    label(root, 24, 20, "(a) 完整算法", "viz-figure-title", "start");
    label(root, 330, 20, "(b) 函数 g", "viz-figure-title", "start");
    word(24, 44, 0);
    word(88, 44, 1);
    // 两个阶段几何相同，第二阶段整体下移 130：w2 = w0⊕g(w1)，w3 = w2⊕w1；w4 = w2⊕g(w3)，w5 = w4⊕w3
    [{shift: 0, first: 2, second: 3, round: 1}, {shift: 130, first: 4, second: 5, round: 2}].forEach(({shift, first, second, round}) => {
      const y = 44 + shift;
      label(root, 24, y - 6, `K${first / 2 - 1}`, "viz-key-text", "start");
      wire(`M 140 ${y + 20} H 195`, [first]);
      gCircle(210, y + 20, [first]);
      label(root, 234, y + 24, `RCON(${round})`, "viz-caption-text", "start");
      wire(`M 50 ${y + 40} V ${y + 76}`, [first]);
      wire(`M 114 ${y + 40} V ${y + 76}`, [second]);
      tag(circleXor(root, 50, y + 88, 12), [first]);
      tag(circleXor(root, 114, y + 88, 12), [second]);
      wire(`M 210 ${y + 35} V ${y + 56} H 119 a 5 5 0 0 0 -10 0 H 74 V ${y + 88} H 62`, [first]);
      wire(`M 50 ${y + 100} V ${y + 130}`, [first]);
      wire(`M 50 ${y + 114} H 88 V ${y + 88} H 102`, [second]);
      wire(`M 114 ${y + 100} V ${y + 130}`, [second]);
      word(24, y + 130, first);
      word(88, y + 130, second);
    });
    label(root, 24, 296, "K2", "viz-key-text", "start");

    // (b) g 函数：w → N0 N1 → RotNib（交换）→ SubNib（两个 S 盒）→ ⊕ RCON → g(w)
    const g = step.g;
    const cx = 424;
    const part = add(root, svg("g", {class: `viz-gfunction ${g ? "" : "is-off"}`}));
    const cell = (x, y, w, h, caption, value) => add(part, svg("g", {class: "viz-word"},
      svg("rect", {x, y, width: w, height: h, rx: 6}), svg("text", {x: x + 4, y: y + 10, class: "viz-cell-tag", text: caption}),
      svg("text", {x: x + w / 2, y: y + h - 9, class: "viz-cell-value", "text-anchor": "middle", text: value})));
    const flow = (d) => path(part, d, "viz-wire", {"marker-end": arrow});
    const nibble = (value, shift) => (g ? nibbleHex((value >> shift) & 15) : "·");
    cell(cx - 40, 44, 80, 34, "w", g ? hex(g.input, 2) : "·");
    flow(`M ${cx - 30} 78 V 100`);
    flow(`M ${cx + 30} 78 V 100`);
    cell(cx - 52, 100, 44, 30, "N0", nibble(g && g.input, 4));
    cell(cx + 8, 100, 44, 30, "N1", nibble(g && g.input, 0));
    flow(`M ${cx - 30} 130 L ${cx + 30} 166`);
    flow(`M ${cx + 30} 130 L ${cx - 30} 166`);
    label(part, cx + 70, 150, "RotNib", "viz-caption-text", "start");
    cell(cx - 52, 168, 44, 30, "N1", nibble(g && g.rotated, 4));
    cell(cx + 8, 168, 44, 30, "N0", nibble(g && g.rotated, 0));
    flow(`M ${cx - 30} 198 V 222`);
    flow(`M ${cx + 30} 198 V 222`);
    [-30, 30].forEach((offset) => add(part, svg("g", {class: "viz-sbox"}, svg("rect", {x: cx + offset - 14, y: 222, width: 28, height: 28, rx: 5}),
      svg("text", {x: cx + offset, y: 241, "text-anchor": "middle", text: "S"}))));
    label(part, cx + 70, 240, "SubNib", "viz-caption-text", "start");
    flow(`M ${cx - 30} 250 V 272`);
    flow(`M ${cx + 30} 250 V 272`);
    cell(cx - 52, 272, 44, 30, "N1′", nibble(g && g.substituted, 4));
    cell(cx + 8, 272, 44, 30, "N0′", nibble(g && g.substituted, 0));
    flow(`M ${cx - 30} 302 L ${cx - 6} 336`);
    flow(`M ${cx + 30} 302 L ${cx + 6} 336`);
    circleXor(part, cx, 348, 13);
    cell(cx + 56, 332, 80, 32, g ? `RCON(${g.round_index})` : "RCON", g ? hex(g.round_constant, 2) : "·");
    flow(`M ${cx + 56} 348 H ${cx + 15}`);
    flow(`M ${cx} 361 V 382`);
    cell(cx - 40, 382, 80, 34, "g(w)", g ? hex(g.output, 2) : "·");
    if (!g) label(part, cx, 66, "本步不经过 g", "viz-caption-text");
    return {root, frame() {}};
  }

  // ------------------------------------------------------------ 图 D.2：数据结构
  function drawStructure(trace, step) {
    const {root, arrow} = makeSvg(560, 408, "S-AES 数据结构：状态矩阵与密钥字（教材图 D.2）");
    const nibbles = nibblesOf(step.block), bits = bin(step.block);
    label(root, 24, 20, `(a) 16 位${step.block_name} → 2×2 状态矩阵`, "viz-figure-title", "start");
    for (let index = 0; index < 16; index++) {
      const x = 24 + index * 32;
      label(root, x + 15, 40, `b${index}`, "viz-cell-tag");
      add(root, svg("g", {class: "viz-bit"}, svg("rect", {x, y: 46, width: 30, height: 28, rx: 4, class: `viz-cell ${index < 8 ? "c0" : "c1"}`}),
        svg("text", {x: x + 15, y: 66, "text-anchor": "middle", text: bits[index]})));
    }
    nibbles.forEach((value, index) => {
      const x0 = 24 + index * 128, x1 = x0 + 126;
      path(root, `M ${x0 + 2} 80 V 86 H ${x1 - 2} V 80`, "viz-brace");
      label(root, (x0 + x1) / 2, 102, `N${index} = ${nibbleHex(value)}`, "viz-text");
    });
    // 左：位表示 [[N0, N2], [N1, N3]]；右：半字节表示 [[S0,0, S0,1], [S1,0, S1,1]]，都按列排列
    const placement = [[0, 2], [1, 3]];
    const matrices = [
      {x: 60, width: 74, caption: "位表示", tag: (n) => `N${n}`, content: (n) => bin(nibbles[n], 4)},
      {x: 330, width: 56, caption: "半字节表示", tag: (n) => SUB_LABELS[n], content: (n) => nibbleHex(nibbles[n])},
    ];
    matrices.forEach((spec) => {
      placement.forEach((row, r) => row.forEach((n, c) => {
        const x = spec.x + c * (spec.width + 4), y = 128 + r * 44;
        add(root, svg("g", {class: "viz-bit"}, svg("rect", {x, y, width: spec.width, height: 40, rx: 5, class: `viz-cell ${c === 0 ? "c0" : "c1"}`}),
          svg("text", {x: x + 4, y: y + 11, class: "viz-cell-tag", text: spec.tag(n)}),
          svg("text", {x: x + spec.width / 2, y: y + 30, class: "viz-cell-value", "text-anchor": "middle", text: spec.content(n)})));
      }));
      label(root, spec.x + spec.width + 2, 228, spec.caption, "viz-caption-text");
    });
    path(root, "M 246 172 H 312", "viz-wire", {"marker-end": arrow});
    label(root, 279, 162, "按列排列", "viz-caption-text");

    label(root, 24, 262, "(b) 16 位密钥 → 字 w₀ w₁，再扩展出 w₂…w₅", "viz-figure-title", "start");
    const keyBits = bin(step.key);
    for (let index = 0; index < 6; index++) {
      const x = 24 + index * 88, known = index < 2;
      const box = wordBox(root, x, 292, `w${index}`, hex(trace.words[index], 2), known, false, 80, 58, 26);
      if (known) box.append(svg("text", {x: x + 40, y: 292 + 49, class: "viz-cell-tag", "text-anchor": "middle", text: keyBits.slice(index * 8, index * 8 + 8)}));
    }
    path(root, "M 26 288 V 283 H 190 V 288", "viz-brace");
    label(root, 108, 277, "原始密钥", "viz-caption-text");
    path(root, "M 202 288 V 283 H 548 V 288", "viz-brace");
    label(root, 375, 277, "密钥扩展（接下来 4 步算出）", "viz-caption-text");
    [["K0", 0], ["K1", 2], ["K2", 4]].forEach(([name, index]) => {
      const x0 = 24 + index * 88, x1 = x0 + 168;
      path(root, `M ${x0 + 2} 358 V 364 H ${x1 - 2} V 358`, "viz-brace");
      label(root, (x0 + x1) / 2, 384, `${name} = w${index} w${index + 1}`, "viz-key-text");
    });
    return {root, frame() {}};
  }

  // ------------------------------------------------------------ 图 D.1：整体结构
  // 槽 0–7 自上而下；加密按槽顺序向下执行，解密按相反方向（向上）执行，A_K0 / A_K1 / A_K2 在两侧位于同一高度
  const OVERVIEW = {width: 560, height: 692, enc: 108, key: 280, dec: 452, boxWidth: 160, boxHeight: 44, top: 106, gap: 62};

  function drawOverview(trace, stepIndex, onSelect) {
    const o = OVERVIEW;
    const {root, arrow} = makeSvg(o.width, o.height, "S-AES 整体结构：加密、解密与密钥扩展（教材图 D.1）");
    const slotTop = (slot) => o.top + slot * o.gap;
    const slotMid = (slot) => slotTop(slot) + o.boxHeight / 2;
    const half = o.boxHeight / 2;
    const doneOps = stepIndex >= 5 ? stepIndex - 5 : -1; // 已经执行的加解密步骤的最大序号
    const statesByMode = {[trace.mode]: trace.states, [trace.roundtrip.operation]: trace.roundtrip.states};
    label(root, o.enc, 16, "加密", "viz-column-title");
    label(root, o.key, 16, "密钥扩展", "viz-column-title");
    label(root, o.dec, 16, "解密", "viz-column-title");

    const frame = (x, slotFrom, slotTo, caption, side) => {
      const y = slotTop(slotFrom) - 8, height = slotTop(slotTo) + o.boxHeight + 8 - y;
      rect(root, x - o.boxWidth / 2 - 8, y, o.boxWidth + 16, height, "viz-frame", 12);
      const textX = side === "left" ? x - o.boxWidth / 2 - 16 : x + o.boxWidth / 2 + 16;
      add(root, svg("text", {x: textX, y: y + height / 2, class: "viz-frame-label", "text-anchor": "middle",
        transform: `rotate(${side === "left" ? -90 : 90} ${textX} ${y + height / 2})`, text: caption}));
    };
    frame(o.enc, 1, 4, "第 1 轮", "left");
    frame(o.enc, 5, 7, "第 2 轮", "left");
    frame(o.dec, 1, 2, "第 2 轮", "right");
    frame(o.dec, 3, 6, "第 1 轮", "right");

    const drawColumn = (mode, x) => {
      const live = mode === trace.mode, upward = mode === "decrypt", states = statesByMode[mode];
      const slotOf = (index) => (upward ? 7 - index : index);
      const side = live ? "" : "is-side";
      const knownUpTo = live ? doneOps : 7; // 旁路一侧显示完整的反向验算
      const inputY = upward ? 638 : 56, outputY = upward ? 56 : 638;
      const endAt = (slot, atFlowEnd) => (upward === atFlowEnd ? slotTop(slot) : slotTop(slot) + o.boxHeight); // 箭头在方框上沿还是下沿
      pill(root, x, inputY, 112, 44, upward ? "16 位密文" : "16 位明文", spaced(states[0]), `viz-terminal ${side}`);
      pill(root, x, outputY, 112, 44, upward ? "16 位明文" : "16 位密文", knownUpTo >= 7 ? spaced(states[8]) : "· · · ·",
        `viz-terminal ${side} ${live && knownUpTo >= 7 ? "is-done" : ""}`);
      const connect = (fromY, toY, hot) => path(root, `M ${x} ${fromY} V ${toY}`, `viz-wire ${hot ? "is-active" : ""} ${side}`, {"marker-end": arrow});
      trace.outline[mode].forEach((item) => {
        const slot = slotOf(item.index), done = item.index <= knownUpTo, active = live && item.index === doneOps;
        pill(root, x, slotMid(slot), o.boxWidth, o.boxHeight, `${item.label} · ${item.name}`, done ? spaced(states[item.index + 1]) : "· · · ·",
          `viz-op ${done ? "is-done" : "is-pending"} ${active ? "is-active" : ""} ${side}`, live ? () => onSelect(5 + item.index) : undefined);
        if (item.index === 0) connect(upward ? inputY - 22 : inputY + 22, endAt(slot, false), active);
        else connect(endAt(slotOf(item.index - 1), true), endAt(slot, false), active);
      });
      connect(endAt(slotOf(7), true), upward ? outputY + 22 : outputY - 22, false);
    };
    drawColumn("encrypt", o.enc);
    drawColumn("decrypt", o.dec);

    // 密钥列：16 位密钥 → w[0,1] → 扩展密钥 → w[2,3] → w[4,5]，并向两侧的 A_K 方框供给轮密钥
    const expanding = stepIndex >= 1 && stepIndex <= 4;
    const keyBoxes = [{name: "w[0,1]", value: trace.round_keys[0], slot: 0, known: true, active: false},
      {name: "w[2,3]", value: trace.round_keys[1], slot: 4, known: stepIndex >= 2, active: stepIndex === 2},
      {name: "w[4,5]", value: trace.round_keys[2], slot: 7, known: stepIndex >= 4, active: stepIndex === 4}];
    pill(root, o.key, 56, 112, 44, "16 位密钥", spaced(trace.key), "viz-terminal");
    keyBoxes.forEach((item) => {
      pill(root, o.key, slotMid(item.slot), 108, 44, item.name, item.known ? spaced(item.value) : "· · · ·",
        `viz-key ${item.known ? "is-done" : "is-pending"} ${item.active ? "is-active" : ""}`);
      [[o.key - 54, o.enc + o.boxWidth / 2], [o.key + 54, o.dec - o.boxWidth / 2]].forEach(([from, to]) =>
        path(root, `M ${from} ${slotMid(item.slot)} H ${to}`, "viz-wire viz-wire-key", {"marker-end": arrow}));
    });
    pill(root, o.key, 212, 108, 44, "扩展密钥", "w₂ … w₅", `viz-key ${stepIndex >= 1 ? "is-done" : "is-pending"} ${expanding ? "is-active" : ""}`);
    [[78, slotTop(0)], [slotTop(0) + o.boxHeight, 190], [234, slotTop(4)], [slotTop(4) + o.boxHeight, slotTop(7)]].forEach(([from, to]) =>
      path(root, `M ${o.key} ${from} V ${to}`, "viz-wire viz-wire-key", {"marker-end": arrow}));
    return {root, frame() {}};
  }

  // ------------------------------------------------------------ 播放器
  // 通用播放器：steps 每项至少有 title；render(step, index, controls) 返回 {node, frame(progress, animated)}
  function createPlayer(host, steps, options) {
    if (host._saesPlayer) host._saesPlayer.destroy();
    host.replaceChildren();
    if (!steps.length) { host.append(el("p", {class: "hint", text: "没有可播放的步骤。"})); return null; }
    const previous = el("button", {type: "button", class: "viz-prev", text: "← 上一步"});
    const play = el("button", {type: "button", class: "viz-play primary", text: "播放"});
    const next = el("button", {type: "button", class: "viz-next", text: "下一步 →"});
    const reset = el("button", {type: "button", class: "viz-reset", text: "回到起点"});
    const speed = el("select", {class: "viz-speed", "aria-label": "动画速度"},
      [0.5, 1, 2, 4].map((factor) => el("option", {value: factor, text: `${factor}× 速度`})));
    speed.value = "1";
    const stage = el("select", {class: "viz-stage", "aria-label": "选择演示步骤"},
      steps.map((step, index) => el("option", {value: index, text: `${String(index + 1).padStart(2, "0")} · ${step.title}`})));
    const title = el("h4", {class: "viz-step-title"});
    const counter = el("span", {class: "tag viz-step-count"});
    const body = el("div", {class: `viz-body ${options.bodyClass || ""}`});
    const caption = el("p", {class: "viz-caption", "aria-live": "polite"});
    const progressBar = el("progress", {class: "viz-progress", max: 1, value: 0, "aria-label": "当前步骤播放进度"});
    const root = el("div", {class: "viz-player"},
      el("div", {class: "viz-toolbar"}, previous, play, next, reset, speed), stage,
      el("div", {class: "viz-heading"}, title, counter), body, caption, progressBar,
      el("p", {class: "hint viz-motion-note", text: options.note || "图中每个值均来自本次真实运算。动画速度只影响展示，不代表计算耗时。"}));
    host.append(root);
    let index = options.start || 0, playing = false, elapsed = 0, lastTime = 0, frameId = null, scene = null;

    function draw(animated) {
      const step = steps[index];
      elapsed = 0;
      progressBar.value = animated ? 0 : 1;
      Object.assign(root.dataset, {stepIndex: String(index), stepId: step.id || String(index), kind: step.kind || "", playing: String(playing)});
      stage.selectedIndex = index;
      title.textContent = step.title;
      counter.textContent = `${index + 1} / ${steps.length}`;
      caption.textContent = options.caption ? options.caption(step, index) : step.description || "";
      scene = options.render(step, index, {select, steps});
      body.replaceChildren(scene.node);
      scene.frame(animated ? 0 : 1, animated && !motionReduced());
      previous.disabled = index === 0;
      next.disabled = index === steps.length - 1;
      if (options.onStep) options.onStep(step, index);
    }

    function pause() {
      playing = false;
      root.dataset.playing = "false";
      play.textContent = "播放";
      cancelAnimationFrame(frameId);
      frameId = null;
      if (scene) scene.frame(1, false);
    }

    function tick(time) {
      if (!playing) return;
      elapsed += Math.min(100, time - lastTime) * Number(speed.value);
      lastTime = time;
      progressBar.value = Math.min(1, elapsed / (options.duration || 3200));
      scene.frame(progressBar.value, !motionReduced());
      if (progressBar.value >= 1) {
        if (index === steps.length - 1) { pause(); return; }
        index += 1;
        draw(true);
      }
      frameId = requestAnimationFrame(tick);
    }

    function select(target) {
      pause();
      index = Math.max(0, Math.min(steps.length - 1, target));
      draw(false);
    }

    play.addEventListener("click", () => {
      if (playing) { pause(); return; }
      pauseAll();
      if (index === steps.length - 1 && progressBar.value >= 1) index = 0;
      playing = true;
      play.textContent = "暂停";
      draw(true);
      lastTime = performance.now();
      frameId = requestAnimationFrame(tick);
    });
    previous.addEventListener("click", () => select(index - 1));
    next.addEventListener("click", () => select(index + 1));
    reset.addEventListener("click", () => select(0));
    stage.addEventListener("change", () => select(stage.selectedIndex));
    const controller = {pause, select, current: () => steps[index], index: () => index,
      destroy() { pause(); players.delete(controller); host._saesPlayer = null; }};
    players.add(controller);
    host._saesPlayer = controller;
    draw(false);
    return controller;
  }

  function pauseAll() { players.forEach((player) => player.pause()); }
  document.addEventListener("visibilitychange", () => { if (document.hidden) pauseAll(); });

  // ------------------------------------------------------------ 第 1 关的组合场景：整体结构 + 当前步骤的图和计算细节
  function createCipherPlayer(host, trace, options = {}) {
    return createPlayer(host, trace.steps, {
      start: options.start || 0,
      bodyClass: "viz-cipher-body",
      caption: (step) => {
        if (step.phase === "cipher") return `${step.description} 输入 ${spaced(step.before)} → 输出 ${spaced(step.after)}`;
        if (step.phase === "key") return `${step.description}：${hex(step.result, 2)}`;
        return step.description;
      },
      render(step, index, controls) {
        const overview = drawOverview(trace, index, controls.select);
        const main = step.phase === "structure" ? drawStructure(trace, step)
          : step.phase === "key" ? drawKeyExpansion(trace, step) : drawRound(trace, step);
        const node = el("div", {class: "viz-grid"},
          el("div", {class: "viz-overview"}, overview.root),
          el("div", {class: "viz-main"}, el("div", {class: "viz-main-figure"}, main.root), window.SAESFigures.stepDetail(trace, step)));
        return {node, frame: main.frame};
      },
    });
  }

  return {createPlayer, createCipherPlayer, pauseAll, makeSvg, add, label, path, rect, circleXor, pill, spaced, nibblesOf};
})();
