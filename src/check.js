// ai-caller-check: AI caller readiness checks for a business website.
// No API keys, no dependencies, Node 18+. Apache-2.0.
//
// Fetches a business site the way an AI assistant would see it: robots.txt,
// the homepage (as a browser and as an AI assistant), and /llms.txt. It never
// places a phone call and never sends anything to the business.
//
// SSRF guard: http/https only, ports 80/443 only, every hostname is resolved
// and every address must be public. The checked address is pinned for the
// connection (custom lookup), so DNS rebinding cannot swap it afterwards.
// Redirects are followed by hand (max 4) and each hop is re-checked.

import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import net from "node:net";
import zlib from "node:zlib";

const TIMEOUT_MS = 6000;
const MAX_REDIRECTS = 4;
const HTML_CAP = 1_500_000;
const TEXT_CAP = 200_000;

export const VERSION = "0.1.0";
const TOOL_UA = `ai-caller-check/${VERSION} (+https://answeredafterhours.com/ai-caller-check/)`;
const UA_BROWSER =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 " + TOOL_UA;
// Says it is ChatGPT-User so we can see whether a firewall blocks that name.
// It is not a verified OpenAI request (those come from OpenAI's IP ranges).
const UA_AGENT =
  "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot " + TOOL_UA;

// Robots tokens we check, with what each one controls.
export const AI_AGENTS = [
  { token: "ChatGPT-User", who: "ChatGPT fetching a page when a user asks" },
  { token: "OAI-SearchBot", who: "ChatGPT search results" },
  { token: "GPTBot", who: "OpenAI model training" },
  { token: "PerplexityBot", who: "Perplexity answers" },
  { token: "Google-Extended", who: "Gemini use of your content (not Google Search ranking)" },
  { token: "ClaudeBot", who: "Anthropic Claude" },
  { token: "Meta-ExternalAgent", who: "Meta AI / Muse crawling" },
  { token: "meta-externalfetcher", who: "Meta AI / Muse fetching a page for a user" },
];

// ---------- SSRF guard ----------

function ipv4ToInt(ip) {
  return ip.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
}
function inV4(ip, cidr) {
  const [base, bits] = cidr.split("/");
  const mask = bits === "0" ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}
const V4_BLOCK = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
  "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
];

export function isPublicIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) return !V4_BLOCK.some((c) => inV4(ip, c));
  if (v === 6) {
    const s = ip.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (mapped) return isPublicIp(mapped[1]);
    if (s === "::" || s === "::1") return false;
    if (/^f[cd]/.test(s)) return false; // fc00::/7 unique local
    if (/^fe[89ab]/.test(s)) return false; // fe80::/10 link local
    if (/^ff/.test(s)) return false; // multicast
    if (/^2001:db8:/.test(s) || /^2001:0?:/.test(s) || /^64:ff9b:/.test(s) || /^2002:/.test(s)) return false;
    if (/^::/.test(s)) return false; // other IPv4-compatible forms
    return true;
  }
  return false;
}

export function normalizeUrl(input) {
  let raw = String(input || "").trim();
  if (!raw) throw new UserError("Enter your business website, for example yourcompany.com.");
  if (raw.length > 300) throw new UserError("That address is too long.");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = "https://" + raw;
  let u;
  try { u = new URL(raw); } catch (_e) { throw new UserError("That does not look like a website address."); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new UserError("Only http and https websites can be checked.");
  if (u.username || u.password) throw new UserError("Remove the username or password from the address.");
  if (u.port && u.port !== "80" && u.port !== "443") throw new UserError("Only standard web ports (80 and 443) can be checked.");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host)) throw new UserError("Enter your domain name, not an IP address.");
  if (!host.includes(".") || /\.(local|localhost|internal|lan|home|corp|intranet)$/i.test(host) || host === "localhost") {
    throw new UserError("Enter a public website address.");
  }
  return new URL(u.origin + "/");
}

export class UserError extends Error {}

function safeLookup(hostname, options, cb) {
  dns.lookup(hostname, { all: true }, (err, addrs) => {
    if (err) return cb(err);
    if (!addrs.length) return cb(new Error("no_address"));
    const bad = addrs.find((a) => !isPublicIp(a.address));
    if (bad) {
      const e = new Error("blocked_address");
      e.code = "EBLOCKED";
      return cb(e);
    }
    if (options && options.all) return cb(null, addrs);
    return cb(null, addrs[0].address, addrs[0].family);
  });
}

// One HTTP request, no redirects. Resolves { status, headers, body, truncated }.
function requestOnce(url, ua, cap) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return reject(new Error("bad_protocol"));
    if (u.port && u.port !== "80" && u.port !== "443") return reject(new Error("bad_port"));
    if (net.isIP(u.hostname.replace(/^\[|\]$/g, ""))) return reject(new Error("ip_literal"));
    const mod = u.protocol === "https:" ? https : http;
    const req = mod.request(
      u,
      {
        method: "GET",
        lookup: safeLookup,
        headers: {
          "User-Agent": ua,
          Accept: "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
          "Accept-Encoding": "gzip, deflate, br",
          "Accept-Language": "en-US,en;q=0.9",
        },
        timeout: TIMEOUT_MS,
      },
      (res) => {
        const enc = String(res.headers["content-encoding"] || "").toLowerCase();
        let stream = res;
        if (enc.includes("br")) stream = res.pipe(zlib.createBrotliDecompress());
        else if (enc.includes("gzip")) stream = res.pipe(zlib.createGunzip());
        else if (enc.includes("deflate")) stream = res.pipe(zlib.createInflate());
        const chunks = [];
        let size = 0;
        let truncated = false;
        const finish = () => resolve({
          status: res.statusCode || 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString("utf8"),
          truncated,
        });
        stream.on("data", (c) => {
          if (truncated) return;
          size += c.length;
          if (size > cap) {
            truncated = true;
            chunks.push(c.subarray(0, Math.max(0, cap - (size - c.length))));
            res.destroy();
            finish();
            return;
          }
          chunks.push(c);
        });
        stream.on("end", () => { if (!truncated) finish(); });
        stream.on("error", (e) => { if (!truncated) reject(e); });
      }
    );
    const hard = setTimeout(() => req.destroy(new Error("timeout")), TIMEOUT_MS + 500);
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => { clearTimeout(hard); reject(e); });
    req.on("close", () => clearTimeout(hard));
    req.end();
  });
}

// Follows redirects by hand, re-validating each hop.
export async function safeFetch(url, { ua = UA_BROWSER, cap = HTML_CAP } = {}) {
  let current = url;
  const hops = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const r = await requestOnce(current, ua, cap);
    if (r.status >= 300 && r.status < 400 && r.headers.location) {
      const next = new URL(r.headers.location, current);
      if (next.protocol !== "http:" && next.protocol !== "https:") throw new Error("bad_redirect");
      hops.push(next.toString());
      current = next.toString();
      continue;
    }
    return { ...r, finalUrl: current, hops };
  }
  throw new Error("too_many_redirects");
}

async function tryFetch(url, opts) {
  try {
    return { ok: true, ...(await safeFetch(url, opts)) };
  } catch (e) {
    return { ok: false, error: e && (e.code === "EBLOCKED" ? "blocked_address" : e.message || String(e)) };
  }
}

// ---------- Detectors ----------

export function detectChallenge(res) {
  if (!res || !res.ok) return null;
  const h = res.headers || {};
  const body = (res.body || "").slice(0, 60000);
  const server = String(h.server || "").toLowerCase();
  if (String(h["cf-mitigated"] || "").toLowerCase() === "challenge") return "Cloudflare challenge";
  if (/<title>\s*(just a moment|attention required)/i.test(body) || /\/cdn-cgi\/challenge-platform\//i.test(body) || /cf-chl-|cf_chl_/i.test(body)) {
    return server.includes("cloudflare") || h["cf-ray"] ? "Cloudflare challenge" : "bot challenge page";
  }
  if (/_Incapsula_Resource|Request unsuccessful\. Incapsula/i.test(body)) return "Imperva bot challenge";
  if (/captcha-delivery\.com|datadome/i.test(body) && res.status >= 400) return "DataDome bot challenge";
  if (/vercel security checkpoint/i.test(body)) return "Vercel security checkpoint";
  if ((res.status === 403 || res.status === 503 || res.status === 429) && (server.includes("cloudflare") || h["cf-ray"])) return `Cloudflare ${res.status} block`;
  if (res.status === 403 || res.status === 401 || res.status === 429) return `HTTP ${res.status} refusal`;
  return null;
}

// robots.txt: group lines by user-agent, pick the most specific group for a
// token, then apply longest-match Allow/Disallow to the path "/".
export function parseRobots(text) {
  const groups = [];
  let cur = null;
  let lastWasAgent = false;
  for (const rawLine of String(text || "").split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    if (key === "user-agent") {
      if (!lastWasAgent || !cur) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(val.toLowerCase());
      lastWasAgent = true;
    } else if (key === "allow" || key === "disallow") {
      if (cur) cur.rules.push({ allow: key === "allow", path: val });
      lastWasAgent = false;
    } else {
      lastWasAgent = false;
    }
  }
  return groups;
}

export function robotsVerdict(groups, token, path = "/") {
  const t = token.toLowerCase();
  let group = groups.filter((g) => g.agents.includes(t));
  let matched = token;
  if (!group.length) { group = groups.filter((g) => g.agents.includes("*")); matched = "*"; }
  if (!group.length) return { blocked: false, matched: null };
  const rules = group.flatMap((g) => g.rules).filter((r) => r.path !== "" || !r.allow);
  let best = null;
  for (const r of rules) {
    if (r.path === "") continue; // "Disallow:" with nothing = allow all
    const pat = r.path.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\\\$$/, "$");
    const re = new RegExp("^" + pat);
    if (re.test(path)) {
      const len = r.path.length;
      if (!best || len > best.len || (len === best.len && r.allow)) best = { len, allow: r.allow };
    }
  }
  return { blocked: best ? !best.allow : false, matched };
}

const LOCAL_TYPES = new Set([
  "localbusiness", "homeandconstructionbusiness", "plumber", "electrician", "hvacbusiness", "roofingcontractor",
  "generalcontractor", "housepainter", "locksmith", "movingcompany", "professionalservice", "legalservice",
  "attorney", "notary", "dentist", "physician", "medicalbusiness", "medicalclinic", "optician", "pharmacy",
  "autorepair", "autobodyshop", "automotivebusiness", "autodealer", "cardealer", "beautysalon", "hairsalon",
  "nailsalon", "dayspa", "healthandbeautybusiness", "healthclub", "exercisegym", "restaurant", "foodestablishment",
  "cafeorcoffeeshop", "bakery", "store", "veterinarycare", "childcare", "drycleaningorlaundry", "emergencyservice",
  "employmentagency", "entertainmentbusiness", "financialservice", "accountingservice", "insuranceagency",
  "realestateagent", "lodgingbusiness", "hotel", "selfstorage", "travelagency", "animalshelter", "petstore",
  "sportsactivitylocation", "tattooparlor", "homegoodsstore", "hardwarestore", "landscaper", "pestcontrol",
]);

function flattenLd(node, out) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) { node.forEach((n) => flattenLd(n, out)); return; }
  out.push(node);
  if (node["@graph"]) flattenLd(node["@graph"], out);
  for (const k of ["mainEntity", "provider", "publisher", "author", "brand", "offers", "itemOffered", "department"]) {
    if (node[k] && typeof node[k] === "object") flattenLd(node[k], out);
  }
}

export function extractJsonLd(html) {
  const nodes = [];
  const re = /<script[^>]*type=["']?application\/ld\+json["']?[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  let invalid = 0;
  while ((m = re.exec(html))) {
    try { flattenLd(JSON.parse(m[1].trim()), nodes); } catch (_e) { invalid++; }
  }
  return { nodes, invalid };
}

function typesOf(n) {
  const t = n["@type"];
  return (Array.isArray(t) ? t : [t]).filter(Boolean).map((x) => String(x).toLowerCase());
}

function visibleText(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&#36;|&dollar;/g, "$")
    .replace(/\s+/g, " ")
    .trim();
}

const BOOKING_HOSTS = /(calendly\.com|acuityscheduling\.com|squareup\.com\/appointments|square\.site|book\.housecallpro\.com|housecallpro\.com|clienthub\.getjobber\.com|getjobber\.com|servicetitan\.com|scheduling\.|setmore\.com|booksy\.com|vagaro\.com|schedulicity\.com|zocdoc\.com|mindbodyonline\.com|fresha\.com|tidycal\.com|\bcal\.com|youcanbook\.me|simplybook\.me|appointy\.com|calendar\.app\.google|calendar\.google\.com\/calendar\/appointments|hubspot\.com\/meetings|meetings\.hubspot\.com)/i;
const BOOKING_PATH = /\/(book|booking|bookings|schedule|scheduling|appointment|appointments|request-service|request-an-appointment|get-a-quote|reserve)(\/|$|\?|-)/i;

export function analyzeHome(html, baseUrl, phoneInput) {
  const out = {};
  const { nodes, invalid } = extractJsonLd(html);
  const local = nodes.filter((n) => typesOf(n).some((t) => LOCAL_TYPES.has(t)));
  const orgWithPhone = nodes.filter((n) => typesOf(n).some((t) => t === "organization" || t === "corporation") && n.telephone);
  out.schema = {
    localBusiness: local.length > 0,
    types: [...new Set(nodes.flatMap(typesOf))].slice(0, 12),
    invalidBlocks: invalid,
    orgWithPhone: orgWithPhone.length > 0,
  };
  const ld = local[0] || orgWithPhone[0] || null;
  out.schema.hasHours = !!(ld && (ld.openingHours || ld.openingHoursSpecification));
  out.schema.hasPhone = !!(ld && ld.telephone);
  out.schema.hasAddress = !!(ld && ld.address);
  out.schema.hasPrice = !!(ld && (ld.priceRange || ld.makesOffer || ld.hasOfferCatalog || ld.offers));

  // tel: links
  const tels = [...html.matchAll(/href=["']\s*tel:([^"']+)["']/gi)].map((m) => decodeURIComponent(m[1]).replace(/[^\d+]/g, ""));
  out.telLinks = [...new Set(tels)].slice(0, 5);
  const digits = String(phoneInput || "").replace(/\D/g, "").replace(/^1(?=\d{10}$)/, "");
  if (digits.length >= 10) {
    const text = visibleText(html).replace(/\D/g, "");
    out.phoneMatch = {
      given: digits,
      inTelLink: out.telLinks.some((t) => t.replace(/\D/g, "").endsWith(digits)),
      onPage: text.includes(digits),
      inSchema: !!(ld && String(ld.telephone || "").replace(/\D/g, "").endsWith(digits)),
    };
  }

  // Booking link
  const hrefs = [...html.matchAll(/<a\b[^>]*href=["']([^"'#][^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi)].map((m) => ({ href: m[1], text: visibleText(m[2]).slice(0, 80) }));
  const links = [];
  for (const a of hrefs) {
    let abs;
    try { abs = new URL(a.href.replace(/&amp;/g, "&"), baseUrl); } catch (_e) { continue; }
    if (/^https?:$/.test(abs.protocol)) links.push({ abs, text: a.text });
  }
  const editorial = /\/(help|blog|docs|guides?|faq|articles?|news|learn|resources|support)\//i;
  const pick = (test) => links.find((l) => test(l));
  const hit =
    pick((l) => BOOKING_HOSTS.test(l.abs.hostname + l.abs.pathname)) ||
    pick((l) => BOOKING_PATH.test(l.abs.pathname) && !editorial.test(l.abs.pathname)) ||
    pick((l) => /^(book|schedule|request)\b.*\b(now|online|appointment|service|visit|call|demo|today)\b/i.test(l.text));
  let booking = hit ? { url: hit.abs.toString().slice(0, 200), text: hit.text } : null;
  if (!booking && ld && ld.potentialAction) {
    const acts = Array.isArray(ld.potentialAction) ? ld.potentialAction : [ld.potentialAction];
    const res = acts.find((a) => /reserve|schedule|order/i.test(String(a["@type"] || "")));
    if (res) booking = { url: String((res.target && (res.target.urlTemplate || res.target)) || "").slice(0, 200), text: "schema.org action" };
  }
  out.booking = booking;

  // Prices in visible text
  const text = visibleText(html);
  const prices = [...text.matchAll(/\$\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?(?:\s?(?:\/|per)\s?(?:mo|month|hr|hour|visit|call))?/gi)].map((m) => m[0]);
  // Ignore tiny figures ("$2 per call", "$4M saved"); a quotable service price is $10 or more.
  out.prices = [...new Set(prices)].filter((p) => Number(p.replace(/[^\d.]/g, "")) >= 10 && !/\$\s?\d+(\.\d+)?\s?[mkb]\b/i.test(p)).slice(0, 6);
  out.priceWords = /\b(diagnostic fee|service call fee|trip charge|flat rate|free estimate|starting at|from \$)/i.test(text);

  // Hours in visible text
  out.hoursText = /\b24\s?\/\s?7\b|\b24 hours\b|\b(mon|monday)\s*(-|–|to|through)\s*(fri|friday|sat|saturday|sun|sunday)\b|\b\d{1,2}(:\d{2})?\s?(am|a\.m\.)\s*(-|–|to)\s*\d{1,2}(:\d{2})?\s?(pm|p\.m\.)/i.test(text);
  out.textLength = text.length;
  return out;
}

// ---------- Scoring ----------

const SOURCES = {
  google: { label: "TechCrunch, July 16, 2025", url: "https://techcrunch.com/2025/07/16/google-rolls-out-ai-powered-business-calling-feature-brings-gemini-2-5-pro-to-ai-mode" },
  muse: { label: "Remio, Meta Muse calling feature", url: "https://www.remio.ai/post/meta-muse-calling-feature-lands-as-instinct-adds-its-own-concierge" },
  museLaunch: { label: "TechCrunch, September 8, 2026", url: "https://techcrunch.com/2026/09/08/meta-debuts-its-muse-ai-agent-will-consumers-trust-it/" },
  blocking: { label: "TechCrunch, October 6, 2026", url: "https://techcrunch.com/2026/10/06/the-next-hurdle-for-ai-agents-getting-websites-to-let-them-in/" },
};

export function buildResult({ url, robots, home, homeAgent, llms, phone }) {
  const checks = [];
  const fixes = [];
  const add = (c) => checks.push(c);

  // 1. Reachable without a bot wall (20)
  const homeChallenge = detectChallenge(home);
  const homeOk = home.ok && home.status >= 200 && home.status < 300 && !homeChallenge;
  if (!home.ok) {
    add({ id: "reach", label: "Site loads for an AI assistant", points: 0, max: 20, status: "fail",
      detail: home.error === "blocked_address" ? "This address points to a private network, so it cannot be checked." : `We could not load your homepage (${home.error}).` });
  } else {
    add({ id: "reach", label: "Site loads for an AI assistant", points: homeOk ? 20 : 0, max: 20, status: homeOk ? "pass" : "fail",
      detail: homeOk ? `Homepage answered ${home.status}${home.hops.length ? ` after ${home.hops.length} redirect${home.hops.length > 1 ? "s" : ""}` : ""}.` : `Homepage answered with ${homeChallenge || "HTTP " + home.status}. An assistant sees a wall, not your business.` });
    if (!homeOk) fixes.push({ weight: 20, title: "Let assistants past your bot wall", body: `Your homepage returned ${homeChallenge || "HTTP " + home.status} to an automated visitor. Cloudflare changed its default on September 15, 2026 in a way that can block AI agents (${SOURCES.blocking.label}). In your firewall or CDN, allow verified AI assistants such as ChatGPT-User, OAI-SearchBot and PerplexityBot.`, source: SOURCES.blocking });
  }

  // 2. Assistant-identified request (10)
  if (homeOk) {
    const agentChallenge = detectChallenge(homeAgent);
    const agentOk = homeAgent.ok && homeAgent.status >= 200 && homeAgent.status < 300 && !agentChallenge;
    add({ id: "agent", label: "A request that says it is ChatGPT gets through", points: agentOk ? 10 : 0, max: 10, status: agentOk ? "pass" : "warn",
      detail: agentOk ? "The same page loaded for a request identifying as ChatGPT-User." : `A request identifying as ChatGPT-User got ${agentChallenge || (homeAgent.ok ? "HTTP " + homeAgent.status : homeAgent.error)}. Some firewalls block unverified bot names; check whether real assistants are allowed.` });
    if (!agentOk) fixes.push({ weight: 10, title: "Check your firewall's AI bot setting", body: `Your site served people but refused a request that named itself as ChatGPT. Many firewalls now block AI user agents by default (${SOURCES.blocking.label}). Allow verified AI assistants so ChatGPT, Perplexity and Meta's Muse can read your hours and prices.`, source: SOURCES.blocking });
  } else {
    add({ id: "agent", label: "A request that says it is ChatGPT gets through", points: 0, max: 10, status: "fail", detail: "Skipped: the homepage did not load." });
  }

  // 3. robots.txt (15)
  let robotsRows = [];
  const robotsRefused = !robots.ok || (robots.status >= 400 && robots.status !== 404 && robots.status !== 410) || !!detectChallenge(robots);
  if (robots.ok && robots.status >= 200 && robots.status < 300 && !detectChallenge(robots) && !/<html/i.test(robots.body.slice(0, 500))) {
    const groups = parseRobots(robots.body);
    robotsRows = AI_AGENTS.map((a) => ({ ...a, ...robotsVerdict(groups, a.token) }));
  } else {
    robotsRows = AI_AGENTS.map((a) => ({ ...a, blocked: false, matched: null }));
  }
  const robotsBlocked = robotsRows.filter((r) => r.blocked);
  // Assistants that answer a live user question matter most.
  const live = ["chatgpt-user", "oai-searchbot", "perplexitybot", "meta-externalfetcher"];
  const liveBlocked = robotsBlocked.filter((r) => live.includes(r.token.toLowerCase()));
  const robotsPts = robotsRefused ? 8 : Math.max(0, 15 - liveBlocked.length * 3 - (robotsBlocked.length - liveBlocked.length) * 1.5);
  add({ id: "robots", label: "robots.txt lets AI assistants in", points: Math.round(robotsPts), max: 15,
    status: robotsRefused ? "warn" : robotsBlocked.length === 0 ? "pass" : liveBlocked.length ? "fail" : "warn",
    detail: robotsRefused ? (robots.ok ? `Your robots.txt itself was refused (${detectChallenge(robots) || "HTTP " + robots.status}), so assistants cannot read your rules.` : `We could not load your robots.txt (${robots.error}).`) : robots.status >= 400 ? "No robots.txt found, so nothing is blocked by it." : robotsBlocked.length ? `Blocked: ${robotsBlocked.map((r) => r.token).join(", ")}.` : "None of the 8 AI agents we check is blocked.",
    rows: robotsRefused ? undefined : robotsRows.map((r) => ({ token: r.token, who: r.who, blocked: r.blocked, rule: r.matched })) });
  if (robotsBlocked.length) fixes.push({ weight: liveBlocked.length ? 12 : 5, title: "Unblock the AI assistants in robots.txt", body: `Your robots.txt blocks ${robotsBlocked.map((r) => r.token).join(", ")}. ${liveBlocked.length ? "Those include assistants that read your site when a customer asks a question, so they cannot quote your hours or prices." : "These mostly control training, which is your call; blocking them does not stop live assistants."} Remove the Disallow lines for the agents you want to recommend you.` });

  // 4-8: homepage content
  const h = homeOk ? analyzeHome(home.body, home.finalUrl, phone) : null;
  if (h) {
    const s = h.schema;
    const schemaPts = s.localBusiness ? (s.hasPhone && s.hasAddress ? 15 : 10) : s.orgWithPhone ? 5 : 0;
    add({ id: "schema", label: "Business facts in schema.org (LocalBusiness)", points: schemaPts, max: 15, status: schemaPts >= 15 ? "pass" : schemaPts > 0 ? "warn" : "fail",
      detail: s.localBusiness ? `Found ${s.types.filter((t) => LOCAL_TYPES.has(t)).join(", ")}${s.hasPhone ? "" : " without a telephone"}${s.hasAddress ? "" : " without an address"}.` : s.types.length ? `Found ${s.types.join(", ")}, but no LocalBusiness type.` : "No schema.org JSON-LD on the homepage." });
    if (schemaPts < 15) fixes.push({ weight: 15 - schemaPts, title: "Add LocalBusiness schema with your phone, address and hours", body: "Assistants read structured data first. Add a JSON-LD block of type LocalBusiness (or Plumber, HVACBusiness, Electrician and so on) with telephone, address, openingHoursSpecification, areaServed and priceRange." });

    const hoursOk = s.hasHours || h.hoursText;
    add({ id: "hours", label: "Hours an assistant can read", points: s.hasHours ? 10 : h.hoursText ? 6 : 0, max: 10, status: s.hasHours ? "pass" : h.hoursText ? "warn" : "fail",
      detail: s.hasHours ? "Opening hours are in your structured data." : h.hoursText ? "Hours appear in the page text but not in structured data." : "No opening hours found on the homepage." });
    if (!s.hasHours) fixes.push({ weight: hoursOk ? 4 : 10, title: "Publish your hours, including after-hours coverage", body: "Put your hours in openingHoursSpecification and on the page. If you take emergency calls overnight, say so, so an assistant does not tell the customer you are closed." });

    let telPts = h.telLinks.length ? 10 : 0;
    let telDetail = h.telLinks.length ? `Tap-to-call link found (${h.telLinks[0]}).` : "No tap-to-call (tel:) link on the homepage.";
    if (h.phoneMatch && !(h.phoneMatch.inTelLink || h.phoneMatch.onPage)) { telPts = Math.min(telPts, 5); telDetail += " The phone number you entered does not appear on the page."; }
    add({ id: "phone", label: "Phone number as a tap-to-call link", points: telPts, max: 10, status: telPts === 10 ? "pass" : telPts ? "warn" : "fail", detail: telDetail });
    if (telPts < 10) fixes.push({ weight: 10 - telPts, title: "Make the phone number a tel: link", body: "Wrap your main number in a tel: link in the header and footer, and use the same number in your Google Business Profile, so assistants that phone businesses dial the line you answer." });

    add({ id: "booking", label: "A booking or quote link", points: h.booking ? 8 : 0, max: 8, status: h.booking ? "pass" : "fail",
      detail: h.booking ? `Found: ${h.booking.text || h.booking.url}.` : "No booking, scheduling or quote-request link found on the homepage." });
    if (!h.booking) fixes.push({ weight: 8, title: "Give assistants a way to book", body: "Add a visible booking or quote-request link (Jobber, Housecall Pro, ServiceTitan, Calendly, or your own form). An assistant can pass a link back to the customer; it cannot fill in a phone tree." });

    const pricePts = h.prices.length ? 8 : h.priceWords || s.hasPrice ? 4 : 0;
    add({ id: "price", label: "A price an assistant can quote", points: pricePts, max: 8, status: pricePts === 8 ? "pass" : pricePts ? "warn" : "fail",
      detail: h.prices.length ? `Prices found: ${h.prices.slice(0, 3).join(", ")}.` : pricePts ? "Pricing language found, but no dollar figure." : "No prices or price ranges on the homepage." });
    if (pricePts < 8) fixes.push({ weight: 8 - pricePts, title: "Publish a price signal", body: "Google's AI calls businesses specifically to ask about pricing and availability. A diagnostic fee, service-call fee or typical range on your site gives assistants something to quote before they even call.", source: SOURCES.google });
  } else {
    for (const [id, label, max] of [["schema", "Business facts in schema.org (LocalBusiness)", 15], ["hours", "Hours an assistant can read", 10], ["phone", "Phone number as a tap-to-call link", 10], ["booking", "A booking or quote link", 8], ["price", "A price an assistant can quote", 8]]) {
      add({ id, label, points: 0, max, status: "fail", detail: "Skipped: the homepage did not load for an automated visitor." });
    }
  }

  // 9. llms.txt (4)
  const llmsOk = llms.ok && llms.status >= 200 && llms.status < 300 && !/<html/i.test(String(llms.body || "").slice(0, 500)) && String(llms.body || "").trim().length > 20;
  add({ id: "llms", label: "llms.txt summary file", points: llmsOk ? 4 : 0, max: 4, status: llmsOk ? "pass" : "warn",
    detail: llmsOk ? "Found /llms.txt." : "No /llms.txt. Optional: few assistants read it today, so it is worth little, but it is cheap." });

  const score = Math.round(checks.reduce((a, c) => a + c.points, 0));
  const max = checks.reduce((a, c) => a + c.max, 0);
  fixes.sort((a, b) => b.weight - a.weight);

  // Context, not a check: assistants also phone businesses. Nothing here is scored.
  const context = {
    title: "AI assistants also phone businesses",
    body: "Google's \"Have AI check pricing\" calls local businesses to ask about price and availability, and Meta's Muse assistant has been placing calls to US businesses since mid-September 2026. This tool reads your website only; it does not test whether your phone line answers.",
    sources: [SOURCES.google, SOURCES.muse, SOURCES.museLaunch],
  };

  return {
    ok: true,
    url,
    checked_at: new Date().toISOString(),
    score: Math.round((score / max) * 100),
    grade: score >= 85 ? "Ready" : score >= 60 ? "Partly ready" : "Not ready",
    checks,
    fixes: fixes.map(({ weight, ...f }) => f),
    context,
    note: "Read public pages only (robots.txt, homepage, llms.txt). No call was placed.",
  };
}

export async function runCheck(inputUrl, phone) {
  const base = normalizeUrl(inputUrl);
  // Resolve once up front so a private or missing host fails fast with a clear message.
  const addrs = await dns.promises.lookup(base.hostname, { all: true }).catch(() => []);
  if (!addrs.length) throw new UserError("We could not find that website. Check the spelling.");
  if (addrs.some((a) => !isPublicIp(a.address))) throw new UserError("That address points to a private network and cannot be checked.");

  const [robots, home, homeAgent, llms] = await Promise.all([
    tryFetch(new URL("/robots.txt", base).toString(), { cap: TEXT_CAP }),
    tryFetch(base.toString(), { cap: HTML_CAP }),
    tryFetch(base.toString(), { ua: UA_AGENT, cap: HTML_CAP }),
    tryFetch(new URL("/llms.txt", base).toString(), { cap: TEXT_CAP }),
  ]);
  return buildResult({ url: base.toString(), robots, home, homeAgent, llms, phone });
}
