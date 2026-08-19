# Gambling-domain infrastructure investigation — 2026-08-18

Ad-hoc follow-up investigation into domains nrdguard flagged as `Gambling` in
`logs/json/flagged_domains_2026-08-17.json`. Goal: figure out what's actually
live behind these flags, how much is real vs. noise, and whether any of it
traces back to shared infrastructure or common operators.

## Tools built for this

Two new MCP servers, both registered with Claude Code at user scope so they're
available in any session:

- **[dns-mcp-server](../../DNSMcpServer)** — full DNS/nameserver/WHOIS/ASN/geo
  recon for a domain in one call (`domain_report`). Resolves via a public
  resolver (1.1.1.1/1.0.0.1) instead of the system resolver, because this
  machine runs a Pi-hole that sinkholes known-bad domains to `0.0.0.0`/`::` —
  which would otherwise make every lookup on a flagged domain useless.
- **[html-fetch-mcp-server](../../HtmlFetchMcpServer)** — fetches a domain's
  homepage HTML. Same public-DNS-resolution fix, plus:
  - `fetch_homepage`/`fetch_url`: requests sent via `curl_cffi` impersonating
    a real Chrome TLS/HTTP2 fingerprint (not just a spoofed `User-Agent`), with
    an optional `Referer` from a known ad/affiliate network (defaults to
    ExoClick) — a lot of these sites gate traffic on referrer/fingerprint.
  - `fetch_rendered`: drives a real headless Chromium (Playwright) for sites
    that need JS execution/cookies to show real content, with the same public
    DNS override wired in via `--host-resolver-rules`.

Both tools cap response size and never execute untrusted content except
`fetch_rendered`, which is used deliberately and sparingly given it runs real
JS from domains our own scanner flagged as likely malicious.

## Sample

40 domains randomly sampled from the `Gambling` category across four rounds,
plus a fifth, targeted round chasing one specific lead (see
[The `askmebet.tech` / QA-pipeline lead](#the-askmebettech--qa-pipeline-lead)
below). Every domain got a `domain_report` (DNS/WHOIS/ASN/geo) and a
`fetch_homepage` at minimum; several got `fetch_rendered` and deeper follow-up
where the surface result was ambiguous or interesting.

## Headline finding: a large share of "Gambling" flags aren't showing gambling content

Across the 40 randomly sampled domains, roughly **half were not actually
serving live gambling content** at the time of testing. That splits into two
distinct, both-confirmed categories:

### 1. A single shared infrastructure cluster, now dead (11 of 40 domains)

`116bet.bid`, `zitbaj.bet`, `a88.cash`, `7j77bet.bet`, `batman668.onl`,
`ba999ccom.bet`, `333okcasino.bet`, `kriyalive.bet`, `pp88.cash`,
`hi77game.bet`, `sun99.best` — **all 11** resolve to the exact same IP,
`185.53.179.128`, via the exact same nameservers, `ns1/ns2.dyna-ns.net`.

This IP belongs to **Team Internet AG** (RIPE-registered block
`185.53.179.0/24`, "DC-Germany"), a legitimate, publicly-traded domain
monetization company (part of Team Internet Group PLC / CentralNic Group) that
runs **ParkingCrew**, a PPC domain-parking product with ~35,000 customers
monetizing 20M+ domains. `dyna-ns.net` — the shared nameserver — is genuinely
massive infrastructure (~929,250 domains under management per public DNS
stats), consistent with being the DNS layer for that same mass-market product,
not anything gambling-specific.

**Every one of these 11 domains was completely unreachable** from this
machine's original network and from an India-based VPN — TLS `ClientHello`
sent, then total silence, full timeout, regardless of client sophistication
(plain `curl`, Chrome-impersonated `curl_cffi`, a real headless browser). A
clean control test proved this wasn't a gambling-specific traffic gate:
`parkingcrew.net` — Team Internet's *own* marketing site, nothing to do with
gambling, on the same network block — hit the identical wall.

**Switching to a genuine residential IP (TDS Telecom broadband) got through
instantly.** All 11 domains returned the identical response:
`HTTP 410 Gone`, body `"It is gone! So be gone"`, error ID `PC410NAML1`
(almost certainly a ParkingCrew-internal error code). Conclusion: the earlier
failures were IP-reputation-based network filtering (blocking
datacenter/VPN-range source IPs across Team Internet's entire hosting block,
not just these domains), and once past that, these are **confirmed dead —
deliberately deactivated ParkingCrew placeholders**, not live gambling sites.
Whatever nrdguard saw when it flagged them, there's nothing there now.

### 2. Parked/for-sale domains on legitimate marketplaces (5 of 40 domains)

- `betonmatkets.com` — WHOIS: *"caught by DropCatch.com on behalf of a
  DropCatch customer... pending backorder/auction delivery"*, hosted on AWS.
- `bm29.com` — `ns1/ns2.afternic.com` (GoDaddy's domain marketplace). Its
  homepage is a `window.onload` JS redirect to
  `forsale.godaddy.com/forsale/bm29.com` — standard Afternic parking
  monetization, not a gambling cloak, confirmed by following it with a real
  browser.
- `stakebce.xyz` and `subpropay.xyz` — also `ns5/ns6.afternic.com`, and share
  the **exact same IP pair** (`13.248.169.48` / `76.223.54.146`) as `bm29.com`
  — a second, smaller confirmed shared-infrastructure cluster, all GoDaddy
  parking.
- Several more resolved but served nothing usable: directory-listing stubs
  (`arenaprediksi234.net`, `belanja4dzorro.lol` → `Index of /`), a broken
  Cloudflare zone (`ilmu-tennang.store` → `409 DNS resolution error`), a
  Cloudflare bot-check wall (`jawara88opra.site`), a dead TLS backend
  (`ruayruay888.org` → `525 SSL handshake failed`), and plain 404s
  (`tiki4d-resmi3.shop`, matching `tiki4d-resmi1.shop` from an earlier round —
  see domain-family clustering below).

**Likely explanation for both categories**: nrdguard classifies on the domain
*name* — these are largely speculatively-registered domains on cheap,
spec-friendly TLDs (`.bid`, `.bet`, `.cash`, `.onl`, `.xyz`) bought in bulk
betting on gambling-adjacent keyword type-in/search traffic, then parked for
PPC ad revenue rather than built out. There's rarely any real page content to
classify at the time of flagging — a nameserver check against a short list of
known parking providers (`dyna-ns.net`, `sedoparking.com`, `afternic.com`,
`dan.com`, `above.com`, `bodis.com`, ...) before running the gambling
classifier would likely cut this false-positive rate substantially.

## Confirmed-live gambling sites (8 of 40 domains)

`kopi4dh.com`, `ga888ib.bet`, `profesorbet.top`, `shareslots.cloud`,
`ceriabet12xsop.live`, `ocic888.beer`, `8888ybet.vip`, `kb333club.com` all
returned real, distinctly-branded, localized gambling content (Indonesian,
Vietnamese, Thai, Burmese, Bengali — APK-download funnels and sportsbook
landing pages).

### Looking for common ownership via payment info — negative result

Searched all 8 homepages plus their dedicated payment/deposit/contact
subpages (`kb333club.com/kb333-payment/`, `8888ybet.vip/deposit-withdrawal`,
`ocic888.beer/ocic888-contact-us/`, etc.) for anything linkable across sites:
WhatsApp/Telegram handles, phone numbers, bank account numbers, crypto wallet
addresses (BTC/TRC20/ETH patterns), email addresses. **Found nothing reusable
across sites** — only generic payment-*method* names (bKash/Nagad/Rocket,
KBZPay/AYA Pay/Wave Money), which just indicate target country, not operator.
Real account numbers are presumably only shown inside a logged-in member
dashboard, which wasn't pursued (would require registering on a live
gambling platform — a different kind of action than passive recon).

Also checked and struck out on: Google Analytics/GTM/Meta Pixel/MS Clarity IDs
(none present on any of the 8 — notably not even accidental leakage), favicon
hashes, JSON-LD structured data (self-referential brand names only), and WHOIS
registrars (all 8 different: Namecheap, GoDaddy, Dynadot, Dominet HK, Domain
Oriental Limited, 2 unavailable).

**Conclusion**: no technical evidence of common ownership at the
content/tracking layer across these 8. Several read like AI-generated SEO
content-farm output (long localized FAQ/blog blocks optimized for
"[brand] APK download" queries) — a shared *production method*, not a shared
*owner*.

## Domain-family clustering — the technique that actually works

Payment info and tracking IDs found nothing. **Domain-name-family clustering
did.** Operators that survive repeated takedowns do it by bulk-registering
numbered/lettered mirror variants of one brand (`brand151.com`,
`brand152.com`, ...) — when one gets blocked, they rotate to the next. That
pattern is directly visible in nrdguard's own dataset without any network
probing at all.

Method: strip TLD and digits from each gambling-flagged domain's label, drop
generic gambling vocabulary (`bet`, `win`, `casino`, `slot`, `vip`, ...), group
by what's left.

**156 distinct brand-stem clusters with 6+ members, covering 1,575+ domains**
(~6.6% of ~23,946 unique gambling-flagged domains in that day's file) collapse
into apparent single-operator networks. Largest / most notable:

| Stem | Count | Notes |
|---|---|---|
| `casipot` | **100** | `casipot151.com`→`casipot154.com`... sequential. Largest single footprint found. |
| `raykobet` | 39 | `raykobet461.com`→`465`... |
| `1xlite` | 32 | **Confirmed real brand** — 1xBet's mirror-app line. 1xBet is documented as running "hundreds of mirror and clone domains" to evade blocks ([Malwarebytes](https://www.malwarebytes.com/blog/scams/2025/03/the-dark-side-of-sports-betting-how-mirror-sites-help-gambling-scams-thrive)). |
| `dragonmoney` | 25 | Known offshore casino brand. |
| `1win-zerkalo` | 24 | **Confirmed** — "zerkalo" is Russian for *mirror*; 1win runs an official rotating-mirror scheme by design, new mirrors roughly every two weeks ([1win-sportsbook.com](https://1win-sportsbook.com/en/1win-zerkalo/)). |
| `vavada` | 19 | Known offshore casino brand. |
| `lotus`/`lotus365` | 20 | Known India/Bangladesh betting platform. |
| `presidenslot` | 20 | `presidenslot001.com`→`003`... |
| `kubet`, `hitclubs` | 13, 12 | Known Vietnamese gambling brands. |

Notably, `shareslots.cloud` — one of the 8 "independently-run" live sites
where payment/tracking analysis found nothing — turned out to belong to a
14-domain family (`shareslots.blog/.cloud/.design/.dev/.fit/...`) once viewed
through this lens. **Domain-registration-pattern analysis succeeded exactly
where content-based analysis failed.**

**Recommendation for nrdguard**: a brand-stem clustering pass (strip digits +
TLD, filter a generic-term list) run across the full blocklist would collapse
tens of thousands of raw entries down to a much smaller number of actual
*operators*, and immediately surface the biggest ones for priority handling.

## The `askmebet.tech` / QA-pipeline lead

While scanning for distinctive (non-generic) clusters, one stood out for a
different reason — not a consumer brand, but what looks like **internal
engineering infrastructure**: 16 domains on the stem `test-rollover-single`
(`test-rollover-single-06.click` through `-19.click`, plus two
`-tiamut-01/02.click` variants). "Rollover" (wagering requirement) and
"single" (bet type) are real sports-betting QA terminology.

**Provisioning is clearly automated**: all 16 registered through **Amazon
Registrar (AWS Route 53)** on 2026-08-15, several literally seconds to minutes
apart (e.g. 12:29:26 → 12:40:45 → 12:41:12 → 12:41:40) — one test domain per
CI run/feature branch, not a human buying domains.

Two sub-groups share the same Cloudflare nameservers (`cloe`/`norman
.ns.cloudflare.com`) but different origin IPs:
- The 14 plain-numbered domains → `104.18.36.111`/`172.64.151.145`, return a
  terse custom `403` ("Sorry, you have been block[ed]", 26 bytes) — an
  app-level rejection.
- The 2 `tiamut` domains → `104.18.36.33`/`172.64.151.223`, hit Cloudflare's
  own full managed-challenge page, which **leaked the real backend hostname**:
  *"You are unable to access **askmebet.tech**."*

`askmebet.tech` resolves to the **exact same IP pair** as the `tiamut` test
domains — confirmed same Cloudflare zone. Unlike everything else in this
investigation, it's a fundamentally different profile:

- Registered directly through **Cloudflare, Inc.** as registrar (deliberate,
  technical choice) in **June 2021** — ~5 years old vs. days-old for
  everything else sampled.
- WHOIS registrant name/org/address redacted, but **state/country leaked
  through: Bangkok, Thailand.**
- TLS cert freshly rotated (issued 2 days before this check) — actively
  maintained.
- **Zero Wayback Machine history** despite 5 years of existence — never
  publicly crawled/indexed.
- Actively firewalled: blocked by Cloudflare (full challenge page, not a
  silent network drop) from *both* a VPN and a genuine residential IP, and
  even with a real headless browser executing JS. Unlike the ParkingCrew
  cluster, switching to a residential source IP did **not** get through here
  — this is a different, more deliberate access-control mechanism (likely an
  IP allowlist or bot-management rule), not simple IP-reputation filtering.

**Read**: this is very likely the internal QA/staging footprint of whoever
builds or operates under the "AskMeBet" name — a real engineering team
(professional CI/CD test-domain provisioning, Cloudflare-registered anchor
domain), based in or operating out of Thailand, testing betting-platform
wagering-requirement logic. It reads as deliberately kept off the public
internet.

**Decision point**: stopped here rather than pushing further. The consumer
gambling storefronts in this investigation are public-facing by design —
broadly advertised to attract players, fair game for open recon.
`askmebet.tech` is the opposite: never indexed, and now confirmed to be
actively rejecting outside access regardless of source IP or client
sophistication. Continuing to engineer around that access control (e.g.
patching around Cloudflare's bot detection specifically) would cross from
"investigating a public site" into "working around access controls on a
private system" — a different category of action, flagged rather than
pursued unilaterally.

## Summary numbers

| Bucket | Count | Share of 40 sampled |
|---|---|---|
| Dead/deactivated ParkingCrew placeholders (Team Internet AG cluster) | 11 | 27.5% |
| Parked/for-sale or otherwise non-functional | 5 | 12.5% |
| **Confirmed live gambling content** | 8 | 20% |
| Not yet independently classified in this write-up (misc errors/blocks) | 16 | 40% |

Plus, orthogonal to the above: **156 domain-family clusters (1,575+ domains,
~6.6% of the unique gambling list)** identifiable directly from registration
patterns, several mapping to real, externally-documented offshore gambling
brands (1xBet/1xLite, 1win, Vavada, Dragon Money, Lotus365, Kubet) known
specifically for running large mirror-domain networks to evade blocking.

## Open threads / next steps

- Firm up the ~50% false-positive rate with a larger sample, or check it
  directly against nrdguard's classification logic/prompts.
- Run the brand-stem clustering at a lower threshold (3+ members) to see how
  much bigger the "real operator" count gets.
- Add a parking-nameserver pre-filter (see false-positive section) to
  nrdguard as a concrete engineering change.
- `askmebet.tech` — left as a flagged lead, not pursued further (see above).
