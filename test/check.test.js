// Offline tests: no network. Run with `npm test`.
import test from "node:test";
import assert from "node:assert/strict";
import { isPublicIp, normalizeUrl, parseRobots, robotsVerdict, analyzeHome, buildResult, detectChallenge, UserError } from "../src/check.js";
import { formatReport } from "../src/format.js";

test("SSRF guard rejects private and reserved addresses", () => {
  for (const ip of ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "::1", "fd00::1", "::ffff:10.0.0.1"]) assert.equal(isPublicIp(ip), false, ip);
  for (const ip of ["93.184.216.34", "2606:4700::6810:84e5"]) assert.equal(isPublicIp(ip), true, ip);
});

test("normalizeUrl adds https and refuses unsafe input", () => {
  assert.equal(normalizeUrl("example.com/some/page").toString(), "https://example.com/");
  for (const bad of ["localhost", "http://10.0.0.1", "ftp://example.com", "https://a:b@example.com", "https://example.com:8080", "printer.local"]) {
    assert.throws(() => normalizeUrl(bad), UserError, bad);
  }
});

test("robots.txt: specific group beats *, longest match wins", () => {
  const g = parseRobots("User-agent: *\nDisallow: /\n\nUser-agent: ChatGPT-User\nUser-agent: PerplexityBot\nAllow: /\n\nUser-agent: GPTBot\nDisallow: /\nAllow: /public\n");
  assert.equal(robotsVerdict(g, "ChatGPT-User").blocked, false);
  assert.equal(robotsVerdict(g, "PerplexityBot").blocked, false);
  assert.equal(robotsVerdict(g, "GPTBot").blocked, true);
  assert.equal(robotsVerdict(g, "ClaudeBot").blocked, true); // falls back to *
  assert.equal(robotsVerdict(parseRobots("User-agent: *\nDisallow:\n"), "GPTBot").blocked, false);
});

const HOME = `<!doctype html><html><head>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Plumber","name":"Acme Plumbing","telephone":"+1-555-010-0199","address":{"@type":"PostalAddress","addressLocality":"Austin"},"openingHours":"Mo-Fr 08:00-17:00"}</script>
</head><body><a href="tel:+15550100199">Call (555) 010-0199</a>
<a href="https://calendly.com/acme/visit">Book online</a><p>Diagnostic fee $89. Open 24/7.</p></body></html>`;

test("analyzeHome finds schema, tel link, booking and price", () => {
  const h = analyzeHome(HOME, "https://acme.example/", "555-010-0199");
  assert.equal(h.schema.localBusiness, true);
  assert.equal(h.schema.hasHours, true);
  assert.deepEqual(h.telLinks, ["+15550100199"]);
  assert.equal(h.phoneMatch.inTelLink, true);
  assert.match(h.booking.url, /calendly\.com/);
  assert.deepEqual(h.prices, ["$89"]);
});

test("detectChallenge spots a Cloudflare wall", () => {
  assert.equal(detectChallenge({ ok: true, status: 403, headers: { server: "cloudflare" }, body: "<title>Just a moment...</title>" }), "Cloudflare challenge");
  assert.equal(detectChallenge({ ok: true, status: 200, headers: {}, body: "<p>hi</p>" }), null);
});

const ok = (body, status = 200, headers = {}) => ({ ok: true, status, headers, body, hops: [], finalUrl: "https://acme.example/" });

test("buildResult scores a well-prepared site 100 and a walled site low", () => {
  const good = buildResult({ url: "https://acme.example/", robots: ok("User-agent: *\nAllow: /\n"), home: ok(HOME), homeAgent: ok(HOME), llms: ok("# Acme Plumbing\n> Plumber in Austin, open 24/7."), phone: "" });
  assert.equal(good.score, 100);
  assert.equal(good.grade, "Ready");
  assert.equal(good.fixes.length, 0);

  const wall = ok("<title>Just a moment...</title>", 403, { server: "cloudflare" });
  const bad = buildResult({ url: "https://acme.example/", robots: ok("User-agent: *\nDisallow: /\n"), home: wall, homeAgent: wall, llms: ok("", 404), phone: "" });
  assert.equal(bad.grade, "Not ready");
  assert.ok(bad.score < 20, String(bad.score));
  assert.equal(bad.checks.find((c) => c.id === "robots").status, "fail");
  assert.match(formatReport(bad, { cta: false }), /FAIL {2}Site loads for an AI assistant/);
});
