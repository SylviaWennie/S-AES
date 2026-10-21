"use strict";

// 小型图表：MITM 候选收敛漏斗、CBC 篡改状态条、统计卡片。
// 规范：单系列单色、数值标在柱端、对数坐标要写明、每张图配表格视图；状态色必配图标和文字。
window.SAESCharts = (() => {
  const {el, svg, formatCount} = window.SAES;
  const SERIES = "#2a78d6";

  // 统计卡片：items = [{value, label, bad?}]
  function statTiles(host, items) {
    host.replaceChildren(...items.map((item) => el("div", {class: item.bad ? "bad" : ""}, el("strong", {text: item.value}), el("span", {text: item.label}))));
  }

  const superscript = (exponent) => String(exponent).replace(/\d/g, (digit) => "⁰¹²³⁴⁵⁶⁷⁸⁹"[Number(digit)]);

  // 横向条形图（对数坐标）：stages = [{label, count}]；0 个候选时不画柱，仅在表格和标注里说明
  function funnel(host, stages, caption) {
    const rowHeight = 38, left = 168, right = 112, width = 560, top = 18, barMax = width - left - right;
    const maxExponent = Math.max(2, Math.ceil(Math.log10(Math.max(...stages.map((stage) => stage.count)))));
    const scale = (count) => (count <= 0 ? 0 : (Math.log10(count) / maxExponent) * barMax);
    const height = top + stages.length * rowHeight + 30;
    const root = svg("svg", {viewBox: `0 0 ${width} ${height}`, role: "img", class: "viz-diagram funnel-chart",
      "aria-label": `${caption}：${stages.map((stage) => `${stage.label} ${formatCount(stage.count)}`).join("，")}`});
    const ticks = [];
    for (let exponent = 0; exponent <= maxExponent; exponent += maxExponent > 6 ? 2 : 1) ticks.push(exponent);
    ticks.forEach((exponent) => {
      const x = left + (exponent / maxExponent) * barMax;
      root.append(svg("line", {x1: x, x2: x, y1: top - 6, y2: top + stages.length * rowHeight, class: "chart-grid"}),
        svg("text", {x, y: top + stages.length * rowHeight + 16, class: "chart-tick", "text-anchor": "middle", text: exponent === 0 ? "1" : `10${superscript(exponent)}`}));
    });
    root.append(svg("line", {x1: left, x2: left, y1: top - 6, y2: top + stages.length * rowHeight, class: "chart-axis"}));
    stages.forEach((stage, index) => {
      const y = top + index * rowHeight + 8, barHeight = 20, length = Math.max(stage.count > 0 ? 4 : 0, scale(stage.count));
      const group = svg("g", {class: "chart-bar-group", tabindex: "0", "aria-label": `${stage.label}：${formatCount(stage.count)}`},
        svg("title", {text: `${stage.label}：${formatCount(stage.count)} 个候选`}),
        svg("text", {x: left - 10, y: y + 14, class: "chart-label", "text-anchor": "end", text: stage.label}));
      if (length > 0) {
        const r = Math.min(4, length / 2);
        group.append(svg("path", {class: "chart-bar", fill: SERIES,
          d: `M ${left} ${y} H ${left + length - r} a ${r} ${r} 0 0 1 ${r} ${r} V ${y + barHeight - r} a ${r} ${r} 0 0 1 ${-r} ${r} H ${left} Z`}));
      }
      group.append(svg("text", {x: left + length + 8, y: y + 15, class: "chart-value", text: formatCount(stage.count)}));
      root.append(group);
    });
    root.append(svg("text", {x: left, y: height - 2, class: "chart-tick", text: "对数坐标：每格是 10 倍"}));
    const table = el("details", {class: "chart-table"}, el("summary", {text: "表格视图"}),
      el("div", {class: "table-wrap"}, el("table", {class: "data-table"}, el("thead", {}, el("tr", {}, el("th", {text: "阶段"}), el("th", {text: "剩余候选密钥数"}))),
        el("tbody", {}, stages.map((stage) => el("tr", {}, el("td", {text: stage.label}), el("td", {class: "mono", text: formatCount(stage.count)})))))));
    host.replaceChildren(el("p", {class: "chart-title", text: caption}), root, table);
  }

  const STATUS = {
    intact: {icon: "✓", label: "未受影响"},
    bitflip: {icon: "⚠", label: "位翻转（可预测）"},
    garbled: {icon: "✕", label: "整块乱码"},
  };

  // 状态条：每个明文分组一格，状态用图标 + 文字 + 左侧色条表示（颜色不是唯一线索）
  function statusStrip(host, rows) {
    const legend = el("div", {class: "strip-legend", "aria-hidden": "false"}, Object.entries(STATUS).map(([key, item]) =>
      el("span", {class: `strip-key status-${key}`}, el("i", {text: item.icon}), item.label)));
    const cells = rows.map((row) => el("div", {class: `strip-cell status-${row.status}`, role: "listitem", tabindex: "0",
      title: `分组 ${row.index + 1}：${STATUS[row.status].label}；原明文 ${row.plain_hex} → 篡改后 ${row.recovered_hex}`},
    el("span", {class: "strip-index", text: `#${row.index + 1}`}), el("span", {class: "strip-state"}, el("i", {text: STATUS[row.status].icon}), STATUS[row.status].label),
    el("code", {text: row.recovered_hex})));
    host.replaceChildren(legend, el("div", {class: "strip", role: "list", "aria-label": "每个明文分组受篡改影响的程度"}, cells));
  }

  return {statTiles, funnel, statusStrip, STATUS};
})();
