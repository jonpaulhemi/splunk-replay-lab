// Prepare dataset from the Datasets page against the fake splunkd (see tests/test_settings_page.py).
// The test server's /test/status/<dataset> stands in for the input writing its status record.
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const base = process.argv[2];
const browser = await chromium.launch();
const page = await browser.newPage();
const seen = {};
const panel = name => `.rl-prepare[data-dataset="${name}"]`;
async function status(name, record) {
  await page.evaluate(async ([n, r]) => {
    await fetch("/test/status/" + n, {method: "POST", body: JSON.stringify(r)});
    window.replayLabSettings.load();
  }, [name, record]);
}
const steps = () => page.$$eval(`${panel("botsv3")} li.rl-step`, l => l.map(x => x.textContent));
try {
  await page.goto(base + "/harness.html");
  await page.waitForSelector("tr[data-dataset]");
  // DEDALE is on: no Prepare until it's switched off
  seen.dedaleDisabled = await page.$$eval(`${panel("dedale")} button`, b => b.every(x => x.disabled));
  seen.dedaleNote = await page.textContent(`${panel("dedale")} .rl-prepare-note`);

  await page.click(`tr[data-dataset="botsv3"] button`);
  // an export is ready, so a re-export asks first; Cancel sends nothing
  await page.click(`${panel("botsv3")} button[data-steps="setup,export,assets"]`);
  seen.confirm = await page.textContent(`${panel("botsv3")} .rl-confirm span`);
  await page.click(`${panel("botsv3")} .rl-confirm-no`);
  seen.afterCancel = await page.textContent(`${panel("botsv3")} .rl-prepare-note`);
  await page.click(`${panel("botsv3")} button[data-steps="setup,export,assets"]`);
  await page.click(`${panel("botsv3")} .rl-confirm-yes`);
  await page.waitForSelector(`${panel("botsv3")} .rl-prepare-result[data-phase=waiting]`);
  seen.waiting = await page.textContent(`${panel("botsv3")} .rl-prepare-result`);

  const request = await page.evaluate(async () =>
    (await (await fetch("/api/datasets/botsv3")).json()).settings.prepare_request);
  await status("botsv3", {state: "preparing", prepare: {request, steps: ["setup", "export", "assets"], feeds: 12,
    state: {setup: {status: "done", changes: 4}, export: {status: "running"}}, log: []}});
  await page.waitForSelector(`${panel("botsv3")} .rl-prepare-result[data-phase=running]`);
  seen.running = await steps();
  if (process.env.SHOT) await page.screenshot({path: process.env.SHOT, fullPage: true});
  seen.buttonsWhileRunning = await page.$$eval(`${panel("botsv3")} .rl-buttons button`, b => b.every(x => x.disabled));

  await status("botsv3", {state: "prepared", prepare: {request, steps: ["setup", "export", "assets"], feeds: 30,
    state: {setup: {status: "done", changes: 4}, export: {status: "done", segments: 1},
            assets: {status: "done", assets: 40, identities: 12}},
    summary: {ok: true, warnings: ["missing add-ons (some detections won't fire): Splunk_TA_nix"]}}});
  await page.waitForSelector(`${panel("botsv3")} .rl-prepare-result[data-phase=done]`);
  seen.done = {head: await page.textContent(`${panel("botsv3")} .rl-prepare-head`),
               warnings: await page.$$eval(`${panel("botsv3")} .rl-warning`, w => w.map(x => x.textContent))};

  await status("botsv3", {prepare: {request, steps: ["assets"], state: {assets: {status: "failed", error: "no hosts"}},
                                    summary: {ok: false}}});
  await page.waitForSelector(`${panel("botsv3")} .rl-prepare-result[data-phase=failed]`);
  seen.failed = await steps();

  await status("botsv3", {state: "off", prepare: {request, refused: "switch the dataset off before Prepare"}});
  await page.waitForSelector(`${panel("botsv3")} .rl-prepare-result[data-phase=refused]`);
  seen.refused = await page.textContent(`${panel("botsv3")} .rl-prepare-result`);
} catch (e) {
  seen.error = String(e);
}
await browser.close();
console.log(JSON.stringify(seen));
process.exit(seen.error ? 1 : 0);
