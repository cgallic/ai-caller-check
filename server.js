// Self-hosted checker: serves the widget at / and the JSON API at /api/check.
// node server.js   (PORT=8787 by default). No keys, no database, stores nothing.
//
// Browsers cannot read another site's robots.txt or homepage (CORS), so the
// widget needs this small server to do the fetching.
import http from "node:http";
import { readFile } from "node:fs/promises";
import { runCheck, UserError } from "./src/check.js";

const PORT = Number(process.env.PORT || 8787);
const RATE_MAX = Number(process.env.RATE_MAX || 12); // checks per IP per 10 minutes
const RATE_WINDOW_MS = 10 * 60 * 1000;
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "*"; // set to your site to restrict embedding
const hits = new Map();

function limited(ip, now = Date.now()) {
  const recent = (hits.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) hits.clear();
  return recent.length > RATE_MAX;
}

function send(res, status, body, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": type,
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": ALLOW_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://localhost");
  if (req.method === "OPTIONS") return send(res, 204, "");
  if (u.pathname === "/" || u.pathname === "/index.html") {
    return send(res, 200, await readFile(new URL("./widget/index.html", import.meta.url), "utf8"), "text/html; charset=utf-8");
  }
  if (u.pathname === "/healthz") return send(res, 200, { ok: true });
  if (u.pathname !== "/api/check") return send(res, 404, { ok: false, error: "not_found" });
  if (req.method !== "GET") return send(res, 405, { ok: false, error: "method_not_allowed" });
  // Behind a proxy, set TRUST_PROXY=1 so the limit applies per client, not per proxy.
  const ip = (process.env.TRUST_PROXY && String(req.headers["x-forwarded-for"] || "").split(",")[0].trim()) || req.socket.remoteAddress || "unknown";
  if (limited(ip)) return send(res, 429, { ok: false, error: "rate_limited", message: "Too many checks. Try again in 10 minutes." });
  try {
    const result = await runCheck(String(u.searchParams.get("url") || "").slice(0, 300), String(u.searchParams.get("phone") || "").slice(0, 30));
    return send(res, 200, result);
  } catch (e) {
    if (e instanceof UserError) return send(res, 400, { ok: false, error: "bad_url", message: e.message });
    return send(res, 502, { ok: false, error: "check_failed", message: "The check could not finish. Try again in a minute." });
  }
});

server.listen(PORT, () => console.log(`ai-caller-check listening on http://localhost:${PORT}`));
