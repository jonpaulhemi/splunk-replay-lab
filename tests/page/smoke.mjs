// Headless smoke test of the Datasets page against the fake splunkd (tests/test_settings_page.py starts it).
// usage: node smoke.mjs <base url>; prints one JSON line of what it saw, exits 1 on a failed check.
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const base = process.argv[2];
const browser = await chromium.launch();
const page = await browser.newPage();
const seen = {};
try {
  await page.goto(base + "/harness.html");
  await page.waitForSelector("tr[data-dataset]");
  seen.rows = await page.$$eval("tr[data-dataset]", rows => rows.map(r => ({
    name: r.dataset.dataset, state: r.querySelector(".rl-state").textContent,
    cells: Array.from(r.children).map(c => c.textContent)})));
  const form = `form[data-dataset="botsv3"]`;
  seen.members = await page.$$eval(`${form} select[name=run_on] option`, o => o.map(x => x.value));
  // a bad value is refused and named next to its field
  await page.click(`tr[data-dataset="botsv3"] button`);
  await page.fill(`${form} input[name=daily_start]`, "9am");
  await page.click(`${form} button[type=submit]`);
  await page.waitForSelector(`${form} .rl-field-error`);
  seen.fieldError = await page.textContent(`${form} .rl-field-error`);
  // a good change is saved
  await page.fill(`${form} input[name=daily_start]`, "10:30");
  await page.check(`${form} input[name=enabled]`);
  await page.selectOption(`${form} select[name=run_on]`, "sh3");
  await page.click(`${form} button[type=submit]`);
  await page.waitForFunction(() => document.querySelector(`tr[data-dataset="botsv3"] td:nth-child(3)`)?.textContent === "sh3");
  seen.saved = true;
} catch (e) {
  seen.error = String(e);
}
await browser.close();
console.log(JSON.stringify(seen));
process.exit(seen.error ? 1 : 0);
