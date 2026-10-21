// 开发辅助：对运行中的实验台截图。用法：
//   node scripts/shot.mjs <端口> <标签页 hash> <输出.png> [选择器] [页面内先执行的脚本]
// 例：node scripts/shot.mjs 8766 basic out.png "#panel-basic" "document.querySelector('.viz-next').click()"
import {launchBrowser} from "./lib/cdp.mjs";

const [port, hash, output, selector, before] = process.argv.slice(2);
if (!port || !hash || !output) { console.error("用法：node scripts/shot.mjs <端口> <hash> <输出.png> [选择器] [先执行的脚本]"); process.exit(2); }

const browser = await launchBrowser({width: 1440, height: 1000});
try {
  const {page} = browser;
  await page.goto(`http://127.0.0.1:${port}/#${hash}`);
  await page.waitFor("document.body.dataset.ready === '1'", {label: "页面脚本就绪"});
  await page.sleep(400);
  await page.waitFor(`document.querySelector('#panel-${hash}:not([hidden]) .viz-player, #panel-${hash}:not([hidden]) .stats strong, #panel-${hash}:not([hidden]) .level-list')`, {timeout: 30000, label: "面板内容"}).catch(() => {});
  if (before) { await page.evaluate(before); await page.sleep(500); }
  await page.screenshot(output, selector ? {selector, padding: 4} : {fullPage: true});
  if (page.problems.length) console.log("页面问题：\n" + page.problems.join("\n"));
  else console.log("截图完成，无脚本错误。");
} finally {
  await browser.close();
}
