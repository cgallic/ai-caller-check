# ai-caller-check

**Can an AI assistant find, read and book this business? One command tells you.**

[![GitHub stars](https://img.shields.io/github/stars/cgallic/ai-caller-check?style=social)](https://github.com/cgallic/ai-caller-check)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen.svg)
![Node 18+](https://img.shields.io/badge/node-%3E%3D18-339933.svg)

ChatGPT, Perplexity, Gemini and Meta's Muse now look up local businesses for their users, and some of them phone the business too. Many sites turn them away by accident: a robots.txt line, a CDN bot wall, no hours or prices an assistant can read. `ai-caller-check` reads a site the way an assistant does and scores it out of 100, with the fixes ranked.

Zero dependencies. No API keys. Never places a call. Free and open source (Apache-2.0).

## Quickstart

```bash
npx github:cgallic/ai-caller-check yourbusiness.com
```

Run it against a whole client list:

```bash
npx github:cgallic/ai-caller-check plumber-one.com hvac-two.com dentist-three.com
```

Self-host the web widget with Docker (builds straight from this repo):

```bash
docker build -t ai-caller-check https://github.com/cgallic/ai-caller-check.git && docker run -p 8787:8787 ai-caller-check
# open http://localhost:8787
```

Don't want to run anything? The same check is hosted free at [answeredafterhours.com/ai-caller-check](https://answeredafterhours.com/ai-caller-check/?utm_source=github&utm_medium=oss&utm_campaign=ai-caller-check&utm_content=readme-hosted).

## What it checks

Four requests, all public: `robots.txt`, the homepage as a browser, the homepage again with a `ChatGPT-User` user agent, and `/llms.txt`.

| Check | Points | What the code actually looks for |
|---|---|---|
| Site loads for an AI assistant | 20 | Homepage returns 2xx with no Cloudflare / Imperva / DataDome / Vercel challenge page and no 401/403/429 |
| A request that says it is ChatGPT gets through | 10 | Same page, requested with a `ChatGPT-User` user agent, also loads |
| robots.txt lets AI assistants in | 15 | Per-agent Allow/Disallow for `/` for ChatGPT-User, OAI-SearchBot, GPTBot, PerplexityBot, Google-Extended, ClaudeBot, Meta-ExternalAgent, meta-externalfetcher. Live-answer agents cost more points than training crawlers |
| Business facts in schema.org | 15 | JSON-LD with a LocalBusiness type (Plumber, Dentist, HVACBusiness and ~60 more), with telephone and address |
| Hours an assistant can read | 10 | `openingHours` / `openingHoursSpecification` in schema (full points) or hours in page text (partial) |
| Phone number as a tap-to-call link | 10 | A `tel:` link on the homepage; with `--phone`, that the number appears on the page |
| A booking or quote link | 8 | Links to Calendly, Jobber, Housecall Pro, ServiceTitan, Acuity, Square and others, or `/book`, `/schedule`, `/get-a-quote` paths |
| A price an assistant can quote | 8 | A dollar figure of $10 or more in page text (full), or words like "diagnostic fee" / "free estimate" (partial) |
| llms.txt summary file | 4 | A non-empty `/llms.txt` |

Grades: 85+ Ready, 60 to 84 Partly ready, under 60 Not ready.

**What it does not do.** It reads the homepage only, not every page. It does not ask ChatGPT or any other assistant anything, so it cannot tell you whether you get recommended. A request that *says* it is ChatGPT-User is not a verified OpenAI request, so a firewall that verifies bots by IP may treat real assistants differently. Results can differ by network: a site that blocks datacenter IPs will look walled from a server even if it loads on your laptop. It does not call your phone line.

## Example output

Real runs on 2026-10-25 from a cloud server (the nytimes.com result is a 403 to that server, which is exactly what an assistant fetching from a datacenter would hit):

```text
$ npx ai-caller-check answeredafterhours.com --no-cta

AI caller readiness: https://answeredafterhours.com/
Score 75/100  [###############.....]  Partly ready

  PASS  Site loads for an AI assistant                   20/20
        Homepage answered 200.
  PASS  A request that says it is ChatGPT gets through   10/10
        The same page loaded for a request identifying as ChatGPT-User.
  PASS  robots.txt lets AI assistants in                 15/15
        None of the 8 AI agents we check is blocked.
  FAIL  Business facts in schema.org (LocalBusiness)      0/15
        Found faqpage, question, but no LocalBusiness type.
  FAIL  Hours an assistant can read                       0/10
        No opening hours found on the homepage.
  PASS  Phone number as a tap-to-call link               10/10
        Tap-to-call link found (+14173862898).
  PASS  A booking or quote link                           8/8
        Found: Book a 48-hour install →.
  PASS  A price an assistant can quote                    8/8
        Prices found: $500, $50, $10,000.
  PASS  llms.txt summary file                             4/4
        Found /llms.txt.

Top fixes
  1. Add LocalBusiness schema with your phone, address and hours
  2. Publish your hours, including after-hours coverage

Read public pages only (robots.txt, homepage, llms.txt). No call was placed.
$ npx ai-caller-check rotorooter.com --no-cta

AI caller readiness: https://rotorooter.com/
Score 67/100  [#############.......]  Partly ready

  PASS  Site loads for an AI assistant                   20/20
        Homepage answered 200 after 1 redirect.
  PASS  A request that says it is ChatGPT gets through   10/10
        The same page loaded for a request identifying as ChatGPT-User.
  PASS  robots.txt lets AI assistants in                 15/15
        None of the 8 AI agents we check is blocked.
  FAIL  Business facts in schema.org (LocalBusiness)      0/15
        Found website, webpage, organization, but no LocalBusiness type.
  FAIL  Hours an assistant can read                       0/10
        No opening hours found on the homepage.
  PASS  Phone number as a tap-to-call link               10/10
        Tap-to-call link found (8007686911).
  PASS  A booking or quote link                           8/8
        Found: Schedule Service.
  FAIL  A price an assistant can quote                    0/8
        No prices or price ranges on the homepage.
  PASS  llms.txt summary file                             4/4
        Found /llms.txt.

Top fixes
  1. Add LocalBusiness schema with your phone, address and hours
  2. Publish your hours, including after-hours coverage
  3. Publish a price signal

Read public pages only (robots.txt, homepage, llms.txt). No call was placed.
$ npx ai-caller-check nytimes.com --no-cta

AI caller readiness: https://nytimes.com/
Score 8/100  [##..................]  Not ready

  FAIL  Site loads for an AI assistant                    0/20
        Homepage answered with HTTP 403 refusal. An assistant sees a wall, not your business.
  FAIL  A request that says it is ChatGPT gets through    0/10
        Skipped: the homepage did not load.
  WARN  robots.txt lets AI assistants in                  8/15
        Your robots.txt itself was refused (HTTP 403 refusal), so assistants cannot read your rules.
  FAIL  Business facts in schema.org (LocalBusiness)      0/15
        Skipped: the homepage did not load for an automated visitor.
  FAIL  Hours an assistant can read                       0/10
        Skipped: the homepage did not load for an automated visitor.
  FAIL  Phone number as a tap-to-call link                0/10
        Skipped: the homepage did not load for an automated visitor.
  FAIL  A booking or quote link                           0/8
        Skipped: the homepage did not load for an automated visitor.
  FAIL  A price an assistant can quote                    0/8
        Skipped: the homepage did not load for an automated visitor.
  WARN  llms.txt summary file                             0/4
        No /llms.txt. Optional: few assistants read it today, so it is worth little, but it is cheap.

Top fixes
  1. Let assistants past your bot wall

Read public pages only (robots.txt, homepage, llms.txt). No call was placed.
```

## Options

```text
--phone <number>   Also check that this phone number appears on the homepage
--json             Print the raw JSON result
--min-score <n>    Exit 1 if any site scores below n (use it in CI)
--no-cta           Hide the links at the end of the report
--no-color         Plain output
```

Fail a deploy when a client site drops below 70:

```bash
npx github:cgallic/ai-caller-check clientsite.com --min-score 70
```

## Use it as a library

```js
import { runCheck } from "ai-caller-check";
const result = await runCheck("yourbusiness.com", "555-010-0199");
console.log(result.score, result.grade, result.fixes[0]?.title);
```

## Embed the widget

`widget/index.html` is one file with no external scripts. Serve it from `node server.js` (or the Docker image), or host it on any page and point it at your checker:

```html
<div id="acc" data-endpoint="https://checker.youragency.com/api/check">
```

A browser cannot read another site's robots.txt or homepage (CORS), so the widget needs the small server to do the fetching. The server stores nothing.

Server settings: `PORT` (default 8787), `RATE_MAX` (checks per IP per 10 minutes, default 12), `ALLOW_ORIGIN` (default `*`), `TRUST_PROXY=1` when behind a reverse proxy.

## Safety

The fetcher only follows http/https on ports 80 and 443. Every hostname is resolved and every address must be public (private, loopback, link-local and metadata ranges are refused), the address is pinned for the connection so DNS rebinding cannot swap it, and each redirect hop (max 4) is re-checked. Responses are size-capped and time out after 6 seconds. Safe to expose as a public endpoint behind the built-in rate limit.

## Go further

The free check reads your website. It cannot see what assistants say about you or what happens when one phones you.

- **[Get the full AI Agent Readiness Report](https://answeredafterhours.com/ai-caller-check/?utm_source=github&utm_medium=oss&utm_campaign=ai-caller-check&utm_content=readme-report#report)** ($199 one-time on answeredafterhours.com): about 20 local buyer prompts run in ChatGPT, Perplexity, Gemini and Google AI Mode showing whether you are named and who is named instead, a firewall and robots.txt review, a facts review for hours, prices and booking, and, with your written OK, one AI price-check test call to your own line.
- **[Have Kai answer your calls](https://www.kaicalls.com/?utm_source=github&utm_medium=oss&utm_campaign=ai-caller-check&utm_content=readme-kai)**: when an assistant phones, voicemail loses the job. KaiCalls answers 24/7 with your prices and openings, books the job and texts you the details.

## Contributing

Issues and PRs welcome, especially new booking platforms, LocalBusiness subtypes and bot-wall signatures. Run `npm test` (offline, no network).

## License

Apache-2.0. Built by [KaiCalls](https://www.kaicalls.com/?utm_source=github&utm_medium=oss&utm_campaign=ai-caller-check&utm_content=readme-footer).
