#!/usr/bin/env node
// CLI: npx ai-caller-check example.com [more.com ...] [--phone 5551234567] [--json] [--min-score 70]
import { runCheck, UserError, VERSION } from "../src/check.js";
import { formatReport } from "../src/format.js";

const HELP = `ai-caller-check ${VERSION}
Can an AI assistant find, read and book this business? Reads robots.txt, the
homepage (as a browser and as ChatGPT-User) and /llms.txt. Never places a call.

Usage:
  ai-caller-check <domain> [<domain> ...] [options]

Options:
  --phone <number>   Also check that this phone number appears on the homepage
  --json             Print the raw JSON result
  --min-score <n>    Exit 1 if any site scores below n (for CI)
  --no-cta           Hide the links at the end of the report
  --no-color         Plain output
  -v, --version      Print version
  -h, --help         Show this help
`;

function parseArgs(argv) {
  const o = { urls: [], phone: "", json: false, minScore: null, cta: true, color: process.stdout.isTTY && !process.env.NO_COLOR };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") o.help = true;
    else if (a === "-v" || a === "--version") o.version = true;
    else if (a === "--json") o.json = true;
    else if (a === "--no-cta") o.cta = false;
    else if (a === "--no-color") o.color = false;
    else if (a === "--phone") o.phone = argv[++i] || "";
    else if (a.startsWith("--phone=")) o.phone = a.slice(8);
    else if (a === "--min-score") o.minScore = Number(argv[++i]);
    else if (a.startsWith("--min-score=")) o.minScore = Number(a.slice(12));
    else if (a.startsWith("-")) throw new UserError(`Unknown option ${a}. Try --help.`);
    else o.urls.push(a);
  }
  return o;
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); process.exit(2); }
  if (o.version) { console.log(VERSION); return; }
  if (o.help || !o.urls.length) { console.log(HELP); process.exit(o.help ? 0 : 2); }
  const results = [];
  let failed = false;
  for (const url of o.urls) {
    try {
      const r = await runCheck(url, o.phone);
      results.push(r);
      if (!o.json) process.stdout.write(formatReport(r, { color: o.color, cta: o.cta && url === o.urls[o.urls.length - 1] }));
      if (o.minScore != null && r.score < o.minScore) failed = true;
    } catch (e) {
      failed = true;
      const msg = e instanceof UserError ? e.message : `Check failed: ${e && e.message}`;
      results.push({ ok: false, url, error: msg });
      if (!o.json) console.error(`\n${url}: ${msg}\n`);
    }
  }
  if (o.json) console.log(JSON.stringify(results.length === 1 ? results[0] : results, null, 2));
  process.exit(failed ? 1 : 0);
}

main();
