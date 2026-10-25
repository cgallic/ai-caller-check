// Plain-text report for the CLI.
export function formatReport(r, { color = false, cta = true } = {}) {
  const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const tag = { pass: c("32", "PASS"), warn: c("33", "WARN"), fail: c("31", "FAIL") };
  const lines = [];
  const filled = Math.round(r.score / 5);
  lines.push("");
  lines.push(c("1", `AI caller readiness: ${r.url}`));
  lines.push(`Score ${c("1", String(r.score))}/100  [${"#".repeat(filled)}${".".repeat(20 - filled)}]  ${r.grade}`);
  lines.push("");
  for (const ch of r.checks) {
    lines.push(`  ${tag[ch.status]}  ${ch.label.padEnd(48)} ${String(ch.points).padStart(2)}/${ch.max}`);
    lines.push(`        ${ch.detail}`);
    if (ch.rows && ch.rows.some((x) => x.blocked)) {
      for (const row of ch.rows) lines.push(`          ${row.blocked ? c("31", "blocked") : c("32", "allowed")}  ${row.token.padEnd(22)} ${row.who}`);
    }
  }
  if (r.fixes.length) {
    lines.push("");
    lines.push(c("1", "Top fixes"));
    r.fixes.slice(0, 3).forEach((f, i) => lines.push(`  ${i + 1}. ${f.title}`));
  }
  lines.push("");
  lines.push(c("2", r.note));
  if (cta) {
    const u = encodeURIComponent(r.url.replace(/^https?:\/\//, "").replace(/\/$/, ""));
    lines.push("");
    lines.push(`This checks your website. It cannot tell you what ChatGPT, Perplexity or Gemini say about you, or what happens when one phones you.`);
    lines.push(`  Full readiness report (prompts, firewall review, test call): https://answeredafterhours.com/ai-caller-check/?utm_source=github&utm_medium=oss&utm_campaign=ai-caller-check&utm_content=cli-report&site=${u}#report`);
    lines.push(`  Have Kai answer the calls 24/7: https://www.kaicalls.com/?utm_source=github&utm_medium=oss&utm_campaign=ai-caller-check&utm_content=cli-kai`);
  }
  lines.push("");
  return lines.join("\n");
}
