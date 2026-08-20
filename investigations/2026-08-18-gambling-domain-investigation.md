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

156 domains randomly sampled from the `Gambling` category across six rounds
(40, then +16, then +100 — plus 6 targeted spot-checks of two specific
name-clusters), plus three separate deep-dive case studies chasing specific
operators to ground: **AskMeBet**, **UFA/UFABET**, and **FAFA178** (the third
found by following a lead out of the first — see below). Every sampled domain
got a `domain_report` (DNS/WHOIS/ASN/geo) and a `fetch_homepage` at minimum;
several got `fetch_rendered` and deeper follow-up where the surface result
was ambiguous or interesting.

## Headline finding: a large share of "Gambling" flags aren't showing gambling content

Across the 156 randomly sampled domains, **59% were not actually serving live
gambling content** at the time of testing (41% confirmed live). That splits
into several distinct, confirmed categories, dominated by one:

### 1. A single shared infrastructure cluster, now dead (37 of 156 domains — 23.7%)

`116bet.bid`, `zitbaj.bet`, `a88.cash`, `7j77bet.bet`, `batman668.onl`,
`ba999ccom.bet`, `333okcasino.bet`, `kriyalive.bet`, `pp88.cash`,
`hi77game.bet`, `sun99.best`, `casinocasino.click`, `qq666.lat`,
`jackpotbet.best`, and 24 more found in a later 100-domain round — **all 37**
resolve to the exact same IP, `185.53.179.128`, via the exact same
nameservers, `ns1/ns2.dyna-ns.net`. (One more, `aa66.cash`, sits on the same
`dyna-ns.net` nameservers but currently has no A record configured —
adjacent to this cluster, not counted in the 37.)

This single cluster is the largest specific bucket found in the entire
sample — **nearly a quarter of every "Gambling"-flagged domain checked**
traces to this one dead IP.

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

### 2. Parked/for-sale domains on legitimate marketplaces (18 of 156 domains — 11.5%)

Four distinct parking platforms confirmed, beyond the Team Internet AG
cluster above:

- **GoDaddy/Afternic** — `betonmatkets.com` (WHOIS: *"caught by DropCatch.com
  on behalf of a DropCatch customer... pending backorder/auction delivery"*),
  `bm29.com` (`ns1/ns2.afternic.com`; homepage is a `window.onload` JS
  redirect to `forsale.godaddy.com/forsale/bm29.com`, confirmed by following
  it with a real browser), `stakebce.xyz` and `subpropay.xyz` (also
  `ns5/ns6.afternic.com`, sharing the exact same IP pair `13.248.169.48` /
  `76.223.54.146` as `bm29.com`).
- **GoDaddy default parking (a separate pair from Afternic)** —
  `swiftbet247.plus`, `betbook250.plus`, `842win.org` all share the exact
  same IP pair `3.33.130.190` / `15.197.148.33` on GoDaddy's own default
  nameservers (`domaincontrol.com`) — same "not built out" signature, distinct
  infrastructure from the Afternic-specific cluster.
- **Parity Domains** (`parity.domains`) — `raykobet476/489/469.com` (all 3
  spot-checked from the 39-domain `raykobet` name-cluster) and
  `chobanicasinoguncel.xyz`, `lotos247.blue`, `bolo800.info`,
  `rajalangit77-naik6.today` all returned the **byte-for-byte identical
  2,963-byte page**, despite being unrelated brand names — the HTML loads
  `lander.parity.domains`, a legitimate domain-aftermarket landing-page
  product.
- Several more resolved but served nothing usable: directory-listing stubs
  (`arenaprediksi234.net`, `belanja4dzorro.lol`, `urbanbatslot.com`,
  `vip333ada.top`, `proses4dultraman.monster` → `Index of /`), broken
  Cloudflare zones/backends (`ilmu-tennang.store` → `409 DNS resolution
  error`; `esbet-sitespasha2026.top` → `520`; `poker88vn.com` → `521`;
  `kssi-play.win` → `523`; `ruayruay888.org` → `525 SSL handshake failed`),
  Cloudflare/WAF bot-check walls (`jawara88opra.site`,
  `betcio-gunceladresin.icu`, `984matbet.cam`, `holiganbetyeni2026adresi.cam`,
  `zhibo-leyutiyu.com`), plain 404s (`tiki4d-resmi3.shop`, matching
  `tiki4d-resmi1.shop` from an earlier round — see domain-family clustering
  below; `simsinoscasino11.com`), a hosting-suspension page
  (`licin4d-game.com` → *"Sorry, the website has been stopped"*, matching the
  `hkmeivus.com` pattern from round one), and one domain
  (`judolbola.xyz`) whose own authoritative DNS answers `127.0.0.1` —
  configured to go nowhere, not a local sinkhole artifact (confirmed via the
  public resolver).
- One false alarm worth noting: `pudingsusu.cfd` isn't gambling content at
  all — it's a default landing page for **Dub.co**, a link-shortener/bio-link
  SaaS tool, caught under a gambling-sounding domain name.

**Likely explanation for both categories**: nrdguard classifies on the domain
*name* — these are largely speculatively-registered domains on cheap,
spec-friendly TLDs (`.bid`, `.bet`, `.cash`, `.onl`, `.xyz`) bought in bulk
betting on gambling-adjacent keyword type-in/search traffic, then parked for
PPC ad revenue rather than built out. There's rarely any real page content to
classify at the time of flagging — a nameserver check against a short list of
known parking providers (`dyna-ns.net`, `sedoparking.com`, `afternic.com`,
`dan.com`, `above.com`, `bodis.com`, ...) before running the gambling
classifier would likely cut this false-positive rate substantially.

## Confirmed-live gambling sites (64 of 156 domains — 41%)

The deep-dive below (payment info, tracking IDs, structured data) was run on
the first 8 confirmed-live domains found: `kopi4dh.com`, `ga888ib.bet`,
`profesorbet.top`, `shareslots.cloud`, `ceriabet12xsop.live`, `ocic888.beer`,
`8888ybet.vip`, `kb333club.com` — all returned real, distinctly-branded,
localized gambling content (Indonesian, Vietnamese, Thai, Burmese, Bengali —
APK-download funnels and sportsbook landing pages). 56 more confirmed live in
later rounds, spanning the same range of languages/markets plus Turkish,
Russian, and Chinese-language sites.

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

### Caveat: cluster size ≠ confirmed-live count

Spot-checked 3 domains each from the two largest clusters (`casipot`, 100
domains; `raykobet`, 39 domains) to verify the technique holds up under
direct testing:

- **All 3 `casipot` domains have no DNS delegation at all** — registered
  (GoDaddy), never activated. Not even nameservers responding.
- **All 3 `raykobet` domains are parked on Parity Domains** (see above), not
  live gambling sites.

So the biggest name-based clusters likely represent a speculator's
*stockpile* — bulk-registered, mostly dormant, a handful activated at a time
— rather than 100 or 39 simultaneously-live threats. If this becomes a
permanent nrdguard signal, weight cluster priority by confirmed-live count,
not raw registration count.

## The `amy`/`nolan` cluster — a confirmed live template factory

While spot-checking a "brand-impersonation-risk" group of clusters whose
stems matched real, recognizable brands (`stake`, `betway`, `starsports`,
`casinomega`, `tigergaming`), a pattern emerged that turned out to be bigger
than any single brand: **every one of them (except `stake`, a false alarm —
see below) shares the exact same Cloudflare nameserver pair**,
`amy.ns.cloudflare.com` / `nolan.ns.cloudflare.com`, and follows an
**identical title template**: *"[Brand Name] – Cá Cược Thể Thao & Casino Trực
Tuyến Hàng Đầu [Việt Nam]"* (Vietnamese), with a Bengali variant confirmed
too.

**`stake` — false alarm, not impersonation.** `stake7799.com`: *"stake779 -
Pusat Download File Berkualitas untuk Pengguna Indonesia"* — an Indonesian
APK-download hub coincidentally using "stake" as a numbered brand name, not
borrowing Stake.com's identity. Lower priority than initially flagged.

**Everything else checked out as real, live, and connected.** Scanning every
domain already looked up in this investigation (272 files) plus a targeted
expansion into the full `sbobet`, `f8bet`, `betway365`, `casinomega`,
`tigergaming`, and `starsports` name-families turned up **46 domains
confirmed on this exact nameserver pair** — including every single
`betway365` TLD variant checked, and most of `casinomega`/`tigergaming`:

| Domain | Title |
|---|---|
| `betway365.best` | *"Betway 365 – বাংলাদেশের সেরা অনলাইন বেটিং প্ল্যাটফর্ম"* (**Bengali** — "Bangladesh's best online betting platform") |
| `betway365.wine`/`.run`/`.bio`/`.fun`/`.onl`/`.bid` | Vietnamese, identical title |
| `starsports.bio`/`.bid` | *"StarSports – Cá Cược Thể Thao & Casino Trực Tuyến Hàng Đầu"* |
| `casinomega.click`/`.run`/`.bio`/`.bid`/`.fun`/`.onl` | *"CasinoMega"*/*"Casino Mega"* variants, same tagline |
| `tigergaming.vip`/`.run`/`.bid`/`.wine` | *"Tiger Gaming – Cá Cược Thể Thao & Casino..."* |
| `sbobetwap.click`, `sbobet-app.net`, `sbobet-khelo.net`, `sbobet-play.net`, `sbobet-win.net` | *"SBOBETWAP"*/*"SBO Bet"* variants |
| `f8betlove.app`, `f8betcon.bet`, `f8beta2com.click/.onl`, `f8beta2con.best/.click`, `f8betbeta2.best/.click`, `f8betcasino.best/.onl` | *"F8Bet..."* variants |
| `ufabet-bangla.net`, `ufabet-jit.net`, `ufabet-win.com` | *"UFA Bet"* (the confirmed-live UFA mirror cluster from the UFA/UFABET case study) |
| `ga888ib.bet`, `hitclubvin.best`, `hocvienxoso1net.bet`, `neu88com.com`, `xoso666com.bet`, `1xbetcm.best`, `90jili.cash`, `bancacom.bet` | Generic-named siblings, same title template, same nameservers |

**This is the largest, best-evidenced single infrastructure cluster in this
entire investigation — and unlike the dead Team Internet AG cluster in §1,
every domain here is confirmed live simultaneously**, not dormant. One shared
hosting/templating operation is running at least **8 distinct "brand
names"** (SBOBET, F8Bet, UFA, Betway, CasinoMega, Tiger Gaming, StarSports,
plus several generic-named siblings) across at least two languages
(Vietnamese primary, Bengali confirmed), some borrowing real, recognizable,
*licensed* company names (Betway specifically — a genuine UK-regulated
bookmaker) for the credibility signal rather than inventing a name from
scratch. `starsports.best` (Bengali/Bangladesh-focused) sits on a *different*
nameserver pair (`mary.ns.cloudflare.com`/`ram.ns.cloudflare.com`) than
`starsports.bio` — meaning the "StarSports" name itself is being reused by
at least two separate, unconnected operations targeting different regional
markets, not just this one factory.

### A second, independent fingerprint: the image pipeline

Cloudflare doesn't expose account ownership to outside observers by
design — there's no legitimate lookup for "which account owns this zone."
But a second passive signature turned out to be more specific than the
nameserver pair alone. Checked TXT records first (nothing — no verification
codes, no email infra, consistent with the zero-footprint pattern everywhere
else in this investigation), then the `og:image` meta tag on every cached
domain in the cluster. All 24 checked follow an **identical, locale-aware
naming convention**:

- `ho-chi-minh-casino-betting-vietnam-coffee-00802.jpg`
- `vung-tau-casino-night-market-02541.jpg`
- `da-lat-card-game-vietnam-coffee-02574.jpg`
- `bogura-cricket-betting-bangladesh-model-00683.jpg` (on the one
  Bengali-language domain, `betway365.best` — Bogura is a real district in
  Bangladesh)

Every filename follows `[city]-casino-betting-[descriptor]-[5-digit-ID].jpg`,
with the city/theme automatically matched to the target language (Vietnamese
cities — Ho Chi Minh, Hanoi, Da Lat, Vung Tau, Phu Quoc, Ha Long Bay, Mekong —
for the Vietnamese sites; Bangladeshi geography for the one Bengali site).
That's evidence of an **automated content-generation pipeline** — something
that picks a city/theme appropriate to the target language and generates a
uniquely-numbered image to match, per domain — not just shared hosting.
Favicons across the same domains are *not* byte-identical (different hashes,
different file sizes), so brand identity (name, favicon, minor copy) is
customized per skin on top of a shared structural backbone (image pipeline,
title template, hosting). Two independent operators coincidentally landing on
the same Cloudflare nameserver pool slot is at least conceivable by chance;
two independent operators independently producing the identical AI-image
naming grammar, locale-matched, across 24 different brands, is not — this
corroborates the nameserver-pair finding rather than resting on it alone.

**Recommendation for nrdguard**: `amy.ns.cloudflare.com`/`nolan.ns
.cloudflare.com` is a high-confidence infrastructure signature worth
tracking directly — a domain landing on this exact pair is very likely part
of this same live template-factory operation regardless of what brand name
it's wearing.

### Full nameserver breakdown

Grouped every domain ever looked up in this investigation (272 domains, 107
distinct nameserver pairings) by its nameserver pair. **Most groupings are
singletons** — a domain on its own uniquely-assigned Cloudflare pair — which
is itself useful context: it confirms multi-domain sharing is the exception,
not routine pool reuse, so the clusters below are meaningful rather than
coincidental.

**Groupings with 4+ domains:**

| Nameservers | Domains | Who |
|---|---|---|
| `amy.ns.cloudflare.com` / `nolan.ns.cloudflare.com` | 46 | The live template-factory cluster (SBOBET, F8Bet, UFA, Betway, CasinoMega, Tiger Gaming, StarSports + generic siblings) |
| `ns1.dyna-ns.net` / `ns2.dyna-ns.net` | 30 | Team Internet AG / ParkingCrew — dead placeholders (see headline finding) |
| `cloe.ns.cloudflare.com` / `norman.ns.cloudflare.com` | 18 | AskMeBet's own zone — `askmebet.tech`, `askmebettournament.com`, all 16 `test-rollover-single` QA domains |
| `dns1.registrar-servers.com` / `dns2.registrar-servers.com` | 11 | Namecheap default parking (`fafaaffiliate.com`, `trustfafa.*`, `chobanicasinoguncel.xyz` — confirmed unrelated squatting, see FAFA178 case study) |
| `ns5.afternic.com` / `ns6.afternic.com` | 5 | GoDaddy/Afternic marketplace parking |
| `ns19/ns20.domaincontrol.com` | 4 | GoDaddy default parking — dormant `ufa1234`/`1234ufabet` variants |
| `micah.ns.cloudflare.com` / `summer.ns.cloudflare.com` | 4 | More F8Bet variants (`f8bet88.bet`, `f8bet90.com`, `f8betb0.net`, `f8betv3.net`) — **a second, separate F8Bet infrastructure grouping** |
| `mary.ns.cloudflare.com` / `ram.ns.cloudflare.com` | 4 | The *other* StarSports operator (`starsports.best/.click/.onl`) plus `tigergaming.onl` |

**Groupings with 2–3 domains** (selected): `mariah`/`ned.ns.cloudflare.com`
(the confirmed live FAFA178 cluster — `fafa178skh.com`, `fafa178skhm.com`,
`fafa178wiw.com`); `ben`/`peaches.ns.cloudflare.com` (a third F8Bet-adjacent
grouping — `8f8bet.vip`, `highbet.vip`, `topxbet.best`); `felipe`/`kara.ns
.cloudflare.com` (Indonesian APK-funnel siblings `autowin88o.com`,
`dewa777o.com`, `gila138n.com`); `dina`/`jeremy.ns.cloudflare.com`
(`fatcai99app.site`, `sbobet886cup.site`, `tanduktotowow.site`);
`byte`/`pixel.dns-parking.com` (`profesorbet.top`, `ufa289n.store` —
Hostinger parking); four more small GoDaddy-default pairs
(`ns27/ns28`, `ns29/ns30`, `ns35/ns36`, `ns53/ns54.domaincontrol.com`), each
holding 2–3 dormant `ufa1234`/`ufabet1234` variants — confirming the dormant
UFA stockpile is spread across *several* different GoDaddy default-IP slots,
not concentrated on one.

**A correction this surfaced**: F8Bet and StarSports each split across
**at least 3 separate nameserver groupings**, not one. "The F8Bet family"
and "the StarSports family" aren't single monolithic operations — each is
multiple distinct infrastructure groups sharing a brand name, the same
pattern already found for FAFA178's `fafaaffiliate.com`/`trustfafa.com`
being unrelated squatting rather than the real platform.

**One notable singleton**: `ns1.ufa356bet.net`/`ns2.ufa356bet.net` — the
only **self-hosted** vanity nameserver pair in the entire dataset (every
other multi-domain grouping runs on a third-party registrar or Cloudflare's
NS pool), consistent with `ufa356bet.net` being a longer-lived, more
independently-operated property (see UFA/UFABET case study).

The remaining 31 domains have no nameservers at all in this dataset — mostly
orphaned zones, expired delegations, or a handful of lookups never retried —
not a meaningful cluster, just absent data.

## Case study: AskMeBet

### The `askmebet.tech` / QA-pipeline lead

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

**Decision point**: stopped trying to get past the block. The consumer
gambling storefronts in this investigation are public-facing by design —
broadly advertised to attract players, fair game for open recon.
`askmebet.tech` is the opposite: never indexed, and confirmed to actively
reject outside access regardless of source IP or client sophistication.
Continuing to engineer around that access control would cross from
"investigating a public site" into "working around access controls on a
private system" — a different category of action, flagged rather than
pursued unilaterally.

### Finding the public-facing brand

"AskMeBet" turns out to be a real, independently-documented online casino/
betting brand — confirmed via ordinary web search, not by touching
`askmebet.tech` again. Two live, fully public sites were found and verified:

| Domain | What it is | Notes |
|---|---|---|
| `askmebet8.com` | "AskMeBet Pokies \| Richgroup Partnership" — Australia-focused pokies site branded "AskMePlay Gaming" | Live, 200 OK, no blocking |
| `askmebettournament.com` | "Askmebet Tournament" — a Nuxt.js web app | Live, 200 OK, **shares the exact same Cloudflare nameserver pair** (`cloe`/`norman.ns.cloudflare.com`) as `askmebet.tech` and the `tiamut` test domains — direct infrastructure confirmation, not just a name match. Also registered via Amazon Registrar, same as the QA-pipeline domains. |

**Casino.guru** (independent casino-review aggregator) has a review of
"AskMeBet Casino" — **Low Safety Index**, recommends against playing there.

### The license claim is fabricated

`askmebet8.com` displays a Curacao gaming license badge: "License: 8048/JAZ"
(Antillephone N.V.'s master license number). Checked directly against
**Antillephone's own official validator**
(`validator.antillephone.com/validate/?domain=askmebet8.com`):

> *"Antillephone cannot verify the licensing status of askmebet8.com...
> Operating status: **INVALID**."*

The license badge is fabricated, not backed by a real sublicense — consistent
with the Casino.guru safety rating.

### Business model: a white-label platform, not a single operator

Wayback Machine snapshots of two now-dead regional marketing sites
(`askmebetkhm.com`, `askmebetkh.com` — both currently have no DNS at all)
contained a structural admission that reframes the whole investigation:

> *"Although **ASKMEBET is a platform provider**, some of its **licensed
> Cambodian operators** offer: complete interfaces in the Khmer language,
> customer support in Khmer, banking in Cambodian riel."*
>
> *"ASKMEBET does not issue bonuses directly, **partner casinos do**."* /
> *"casino sites **powered by ASKMEBET**."*

**AskMeBet is a B2B white-label gambling platform/aggregator, not a single
retail brand.** The actual retail operators — the entities that would need a
license, hold player funds, and legally exist (or not) — are separate
companies plugged into AskMeBet's backend. This directly explains the QA
infrastructure found above (`test-rollover-single`, testing wagering logic
that any downstream operator's storefront would need) and why no single
"AskMeBet" corporate entity could ever be found — there may not be one to
find; there's a platform vendor, and an unknown number of separate operators
running on top of it.

The same snapshots also contain evidence of genuine Cambodia operations, not
fabricated ones: real Cambodian banking rails named specifically ("deposits
via ABA, Wing etc." — both real, major Cambodian banks/e-wallets), a
Telegram-first contact model, and real third-party game studios aggregated
(PG Soft, Spadegaming, JILI, Pragmatic Play, EvoPlay, Live22).

### Is the Cambodia/Thailand link a misdirect?

Worth weighing directly, since a single WHOIS field is thin evidence on its
own. Arguing against deliberate misdirection: the Bangkok leak surfaced on a
**private domain that was never meant to be found** (`askmebet.tech` has zero
Wayback history and isn't linked from anywhere public) — decoys are placed
somewhere an investigator is expected to look, not buried in a redacted field
nobody was supposed to see. It's also corroborated by real banking
integration (ABA/Wing) that would be pointless to fabricate. Cambodia banned
online gambling entirely from January 2020 (Directive No. 07, August 2019 —
no new licenses issued, existing ones not renewed), and Thailand has no legal
path to a private online-gambling license either, so neither country can host
a *legitimately registered* operator regardless. Most likely read: the
Thailand/Cambodia signal describes genuine **operational geography** (where
a dev/ops team or contractor sits) rather than **beneficial ownership** —
those are commonly and deliberately different in this kind of structure.

### The propaganda article

A user-supplied article, [dutable.com: "Askmebet is Not a Pyramid Scheme –
Guaranteed Real Payouts"](https://dutable.com/askmebet-is-not-a-pyramid-scheme-guaranteed-real-payouts/),
turned out to be a paid placement rather than journalism — `dutable.com` is a
generic multi-topic content mill (same profile as the `siit.co` guest-post
site used earlier for a similar AskMeBet placement), byline "Spero Agancy"
[sic] doesn't match any real agency. But it leaked real information while
attacking a named rival:

- Repeatedly disparages **"UFA"** by name as an inferior, "unclear," unlicensed
  competitor — see the UFA/UFABET case study below.
- Names sub-brands under one wallet system: `Askmeslot`, `Askmelotto`,
  `Askmeplay` (none appear in nrdguard's own blocklist).
- Claims **"over 10,000 verified partner websites"** — self-reported and
  unverifiable, but if even roughly true, a striking validation of the
  domain-family-clustering theory above at a much larger scale than anything
  found directly in this sample.
- Reiterates the same fabricated license set (Curacao, Malta Gaming, GLI,
  BBM Testlabs) — and misrepresents GLI/BBM Testlabs specifically, which are
  game-testing/certification labs, not gambling regulators.

### The Telegram link doesn't actually go to AskMeBet

The `askmebetkhm.com` Wayback snapshot has a *"Contact via Telegram"*
button. Its `href` isn't a direct Telegram link — it's a cloaked redirect
through `replug.link/e2eb17ed`, a link-tracking/cloaking service. Resolving
that redirect (a HEAD request, not an actual click-through):

> `location: https://telegram.me/FAFA178_CONVBOT?start=phsseo`

That's a completely different, unrelated brand — **FAFA178** — routed through
a bot literally named "CONVBOT" (conversion bot) with what looks like an
affiliate/traffic-source tracking parameter (`phsseo`).

**This revises how `askmebetkhm.com`/`askmebetkh.com` should be read.** They're
very likely not AskMeBet's own regional marketing at all — they're
independent SEO/affiliate content sites that rank for "AskMeBet" search
demand (consistent with the AI-generated-filler style already flagged) and
monetize the traffic by funneling it to whichever platform actually pays an
affiliate commission — in this case FAFA178, not AskMeBet. The "platform
provider... licensed Cambodian operators" quote pulled from that site earlier
is probably still an accurate general description (these SEO writers
sometimes get real details right), but should be held a little more loosely
given the site publishing it isn't first-party. This directly led to the
[FAFA178 case study](#case-study-fafa178) below.

### Corporate registry search — dead end, and why

Checked Curaçao's Chamber of Commerce (KVK), Hong Kong's Companies Registry,
and general company databases for any entity named "AskMeBet." None of these
registries are self-service public databases reachable by a simple query —
Curaçao's "search" is a request-a-search page with no live form; Hong Kong's
is a paid, session-based government portal. No entity found anywhere. Given
the fabricated license and fully-redacted WHOIS on every related domain, this
is consistent with — not contradicted by — deliberate structuring to avoid
exactly this kind of lookup.

## Case study: UFA / UFABET

The named rival from the propaganda article turned out to have a completely
different, much better documented paper trail than AskMeBet.

### Infrastructure sweep

Unlike AskMeBet (zero `askme`-branded domains ever appeared in nrdguard's own
data — found entirely via external search), **UFA/UFABET already has a real
footprint in nrdguard's blocklist**: 20 domains matching `ufabet*`/`ufa1*`/
`ufa2*`. Ran the same DNS + HTML sweep used throughout this investigation:

- **10 of 20 (exactly half) are dormant** on the same GoDaddy default-parking
  IP pair (`3.33.130.190`/`15.197.148.33`) already identified earlier in the
  random sample — `1234ufabet.com`, `ufa123.casino`, `ufa1234.bet/.club/.fun
  /.games/.plus/.win`, `ufabet1234.bet/.com`.
- `ufa289n.store` sits on Hostinger's `dns-parking.com` — the same parking
  nameserver found under `profesorbet.top` in an earlier round.
- `ufabetsites.com` has fully expired — it now redirects straight to its own
  listing on **ExpiredDomains.com**.
- Two domains (`ufa222x.org`, `ufabet236-th.xyz`) sit behind an active
  bot-challenge product (`sgcaptcha`).
- **A confirmed-live mirror cluster**: `ufabet-bangla.net`, `ufabet-jit.net`,
  `ufabet-win.com` share the same nameservers (`amy`/`nolan.ns.cloudflare.com`)
  and registrar (Dynadot), and all three are **simultaneously live**, serving
  near-identical Vietnamese-language pages — same exact title (*"UFA Bet – Cá
  Cược Thể Thao & Casino Trực Tuyến Hàng Đầu"*), same template, minor copy
  variations. This is the strongest same-operator-confirmed-live evidence
  found anywhere in this investigation — stronger than anything on the
  AskMeBet side, where no two branded domains were ever caught live with
  matching content simultaneously.

### Real law enforcement history — a different tier of finding entirely

Unlike AskMeBet, which stayed a ghost through every technique tried, UFA/
UFABET has been the subject of actual Thai government investigation, with
named individuals, seized assets, and criminal charges:

- **Thailand's Department of Special Investigation (DSI)**, Special Case No.
  8/2566 (Nov 15, 2023): charged **Police Captain Nattasakdithat** (an agent
  for the UFABET network) and **Mr. Pakpoom** (described as UFA's financial
  director) with unlicensed electronic gambling and money laundering. DSI's
  own summary: Nattasakdithat *"marketed the online gambling website to find
  customers... received payments through his own bank account and
  transferred the payments to the owners."* Over 40 million baht seized;
  *"many agents had fled from their residences and some had fled abroad."*
  ([DSI official release](https://www.dsi.go.th/en/Detail/de2f5a3f0c742107e2c25245d4c0bf54))
- Independent reporting on the same case (Casino.org, VegasSlotsOnline): DSI
  seized **two resorts/villas in Phuket** (reported values $28–57M across
  outlets), tied to an operation overseeing roughly **80 mule bank accounts**
  (some holding over 1 billion baht), with **83 bank accounts** (mostly
  foreign-owned) seized in the wider probe.
- **A larger, connected network**: multiple Bangkok Post/Thaiger stories
  identify a figure known as "Inspector Sua" as **Pol Lt Col Wasawat
  Mukurasakul**, a Royal Thai Police officer (suspended pending investigation,
  reportedly fled the country), whose network is independently described as
  supervising UFA Bet's affiliates. That network is reported to involve
  **60+ linked firms** (7 directly running gambling sites), estimated revenue
  over **10 billion baht/year**, and led to **30 arrests across 39 raided
  locations**.
- Multiple independent sources describe UFA Bet as **"one of Thailand's three
  biggest gambling networks."**
- One unverified loose thread: a "UFABET LTD" UK Companies House entry
  (incorporated April 2026) turned up in search, but nothing ties it to the
  actual Thai network beyond the name match — generic-keyword shell
  registrations are common and usually unrelated. Flagged, not relied on.

### Agent recruitment — advertised in the open

Unlike AskMeBet and FAFA178 (below), UFA runs a whole ecosystem of dedicated
recruitment sites (`ufabetkhmer.com/en/agent-ufa/`, `ufabets188.com/en
/registration/`, `ufabetagent.com` — all since expired, recovered via
Wayback). The pitch is standardized across all of them:

- **Up to 85% commission share**, explicitly framed as possible only because
  "we are an agent of UFABET directly without other partners."
- **A tiered structure**: register as a basic Agent, get promoted to
  **"Super"** status, then recruit and manage your own sub-agent network and
  earn commission on their activity too — multi-level, not flat.
- **A credit/leverage system**: *"you place 20,000 baht deposit, you will
  receive 100,000 baht to manage with your customers"* — 5x leverage on
  whatever the agent deposits, to extend credit to their own players.
- **A real backend admin panel**: *"manage your customers from UFABET
  backend such as credit topping up, credit withdrawal, suspend use of
  members, create a user for a member to bet"* — a genuine self-service
  dashboard, not just a referral link.
- **Openly published contact channels**: a phone number (`097-513-1801`) and
  a direct LINE add-friend link (`https://line.me/ti/p/q4tTwNwsyu`) — LINE
  being the dominant messaging app in Thailand, the same functional role
  Telegram plays for AskMeBet/FAFA178's Cambodia-facing operations. Also
  surfaced another brand variant: `UFA247.com`.

This is a franchise/MLM-shaped recruitment model — recruit players, then
recruit recruiters, with leveraged credit and a management dashboard doing
the work — which directly explains the DSI case above: a network described
as "agents" managing "mule accounts," 60+ firms deep, because the growth
model is designed to spawn semi-independent sub-operators.

### Why UFA and AskMeBet look so different

AskMeBet: no license, no registrant, no affiliate footprint, no news
coverage — a platform vendor deliberately kept invisible. UFA/UFABET: large
and established enough to have drawn real state investigative attention,
with an internal agent/commission economy documented both by the operation
itself (its own recruitment sites) and by investigators. Independently
described as one of the *three biggest* networks in the country — AskMeBet,
by comparison, reads like a smaller or newer platform still operating below
that threshold of visibility. (See the three-way comparison after the
FAFA178 case study below for how FAFA178 fits into this picture.)

## Case study: FAFA178

Found by accident: the "Contact via Telegram" button on an AskMeBet-branded
SEO site turned out to redirect to a Telegram bot for a different, unrelated
platform (see [The Telegram link doesn't actually go to
AskMeBet](#the-telegram-link-doesnt-actually-go-to-askmebet) above). That
platform, FAFA178, turned out to be worth investigating in its own right.

### Profile

FAFA178's own marketing claims **"over 12 years operating in Southeast
Asia"** — if accurate, older than either AskMeBet or UFA — backed by a
noticeably broader real third-party provider roster than either of the other
two platforms: PG Soft, Pragmatic Play, JILI, CQ9, Habanero, NetEnt, UU
Slots, AFB Gaming, VPLUS (slots); EVO Gaming, SA Gaming, DG99, Sexy Casino,
ALLBET (live casino); AFB1188, SABA, SBO, TF E-Sports (sportsbook). Supports
Bitcoin and Tether (USDT), and four parallel support channels (live chat,
email, Telegram, WhatsApp) rather than one.

**The license claim is vaguer than AskMeBet's — and that's a more defensible
evasion.** No specific license number anywhere, just *"operates under an
international license"* with no regulator named. AskMeBet's mistake was
citing a specific, checkable number (Curacao `8048/JAZ`) that we could
directly disprove via Antillephone's validator; FAFA178 never gives us
anything that concrete to disprove in the first place.

**A confirmed "brand family," bigger than AskMeBet's sub-brands.** FAFA178's
own site navigation lists six sister brands directly (Fafa178, Fafa321,
Fafa188, Fafa288, Fafa877, 8Fafafa) under a menu literally labeled "Fafa
Brand Family" (ตระกูลแบรนด์ Fafa). Further search surfaced at least four more
active variants: FAFA365, FAFA456, FAFA123, FAFA333.

### Infrastructure

`fafa178skh.com` and `fafa178wiw.com` are byte-identical live mirrors (same
title, same content) — the same live-mirror pattern found with UFA.
`fafa178skhm.com` was registered at the exact same second as one of its
siblings — automated bulk registration, consistent with every other cluster
in this investigation. One domain, `fafa178wiw.com`, is genuinely older
(March 2025) — the same two-tier pattern found with `ufa356bet.net`: a
longer-lived core property underneath a constantly-refreshed layer of
disposable mirrors.

### Ownership — a ghost, same as AskMeBet

No corporate registry hit anywhere (Co., Ltd, N.V., or otherwise), no
independent review coverage (nothing on Casino.guru or AskGamblers), no
law-enforcement or news coverage found by any search. Zero `fafa178`-branded
domains were ever flagged by nrdguard directly — same blind spot as
AskMeBet.

### The `fafaaffiliate.com` lead — a clean dead end

nrdguard's blocklist does contain a broader, unbranded `fafa*` cluster (19
domains, including `fafaaffiliate.com` and `trustfafa.com`/`trustfafa.online`
— names that looked like they could be FAFA178's real agent/trust-building
infrastructure). Checked 8 of them directly:
`fafaaffiliate.com`, `trustfafa.com`, `trustfafa.online`, `fafa-bet.online`,
`fafa-bet.vip`, `fafa-spins.com`, `fafaonline.casino`, `fafaonlinecasino.com`
— **all eight return the identical 2,963-byte Namecheap/Parity Domains
parking placeholder.** ("Parity Domains" — `lander.parity.domains` — turns
out to be Namecheap's own default parked-page product, not a fully
independent third party as first assumed.)

**This is a clean, informative negative result, not a failed search.**
nrdguard's `fafa*` cluster and the real, live FAFA178 platform
(`fafa178thb.com`, `fafa178skh.com`, etc. — found only through external web
search) are **two entirely separate populations of domains** that happen to
share a generic, catchy syllable. Nobody registered `fafaaffiliate.com` on
behalf of the real platform; it's speculative squatting, unconnected to the
actual operator. The real FAFA178 brand family remains completely outside
anything nrdguard has ever flagged.

### No public agent/affiliate program found — a real contrast with UFA

Searched extensively (English and Thai-language queries, the brand family
names together, and FAFA178's own site source for any agent/partner links)
and found **nothing** — no recruitment domains, no published commission
structure, no contact channel for prospective operators, anywhere. FAFA178's
own consumer-facing sites don't mention an agent or partner program at all,
unlike AskMeBet's SEO sites (which at least *describe* the platform-provider
model to players).

### Three platforms, three different postures

| | Verifiable license | Corporate registry hit | News/legal coverage | Public agent recruitment | In nrdguard's data |
|---|---|---|---|---|---|
| **UFA/UFABET** | Various claims, unverified | None found | **Yes** — DSI charges, seized resorts, "Inspector Sua" network | **Extensive** — dedicated sites, published terms | Yes — 20 domains |
| **AskMeBet** | Fabricated (proven invalid) | None found | None found | None on its own sites | **No** — zero domains |
| **FAFA178** | Vague, unfalsifiable | None found | None found | **None found anywhere** | **No** — zero domains for the real brand family |

UFA is the most *operationally* exposed of the three — real law enforcement
history and an openly-advertised recruitment funnel — precisely because its
growth model depends on being findable by prospective agents. AskMeBet and
FAFA178 are both close to invisible by comparison, but for what look like
different reasons: AskMeBet's exposure came from sloppy tracking-link hygiene
(the cloaked Telegram redirect that led to this whole thread) and a
disprovable license claim, while FAFA178 avoided both mistakes — nothing
checkable, nothing traceable, and evidently no public recruitment funnel to
leak through in the first place.

## Summary numbers

Across 156 randomly-sampled domains (six rounds: 40, +16, +100):

| Bucket | Count | Share |
|---|---|---|
| Dead/deactivated ParkingCrew placeholders (Team Internet AG cluster) | 37 | 23.7% |
| Other parked (Afternic, GoDaddy-default, Parity Domains) | 18 | 11.5% |
| Dead/suspended/404 | 6 | 3.8% |
| Broken backend (5xx errors) | 6 | 3.8% |
| Empty directory listings | 6 | 3.8% |
| Blocked/inconclusive (WAF challenges, timeouts, thin responses) | 18 | 11.5% |
| **Confirmed live gambling content** | **64** | **41.0%** |

**59% of "Gambling"-flagged domains sampled are not showing live gambling
content**, and almost a quarter of everything sampled traces to one dead IP.

Plus, orthogonal to the above: **156 domain-family clusters (1,575+ domains,
~6.6% of the unique gambling list)** identifiable directly from registration
patterns, several mapping to real, externally-documented offshore gambling
brands (1xBet/1xLite, 1win, Vavada, Dragon Money, Lotus365, Kubet) known
specifically for running large mirror-domain networks to evade blocking —
though spot-checks show the largest clusters skew heavily toward
dormant/parked rather than simultaneously-live (see caveat above).

## Open threads / next steps

- The ~59% false-positive-adjacent rate is now backed by a 156-domain sample
  (up from an initial 40) and has stayed consistent as the sample grew —
  reasonably solid. Could still be checked directly against nrdguard's
  classification logic/prompts for a root-cause fix.
- The `amy`/`nolan.ns.cloudflare.com` cluster (46 confirmed domains, live,
  8+ brand names) is worth tracking as its own signature going forward — it's
  the single highest-confidence "same operator" infrastructure fingerprint
  found in this investigation, and the expansion search wasn't exhaustive
  (only `sbobet`/`f8bet`/`betway365`/`casinomega`/`tigergaming`/`starsports`
  families were checked; other brand-stem clusters from the 126-strong
  unexplored list likely add more members).
- Run the brand-stem clustering at a lower threshold (3+ members) to see how
  much bigger the "real operator" count gets, and weight by confirmed-live
  count rather than raw registration count (see caveat above).
- Add a parking-nameserver pre-filter (see false-positive section) to
  nrdguard as a concrete engineering change — candidates confirmed in this
  investigation: `dyna-ns.net`, `afternic.com`, `domaincontrol.com` (GoDaddy
  default), `parity.domains`/`lander.parity.domains`, `dropcatch.com`,
  `dns-parking.com` (Hostinger).
- `askmebet.tech` — left as a flagged lead, not pursued further (see
  AskMeBet case study above).
- Consider adding `Askmeslot`, `Askmelotto`, `Askmeplay`, a broader UFA
  mirror sweep (only 20 of an unknown total UFA domains were in-scope here),
  and the confirmed FAFA brand family (`Fafa178/321/188/288/877/365/456/123
  /333/8Fafafa`) to future sampling rounds — all three platforms are
  confirmed larger than what nrdguard has caught so far, and FAFA178's real
  domain family has **zero** overlap with the `fafa*` cluster nrdguard
  already flags (that cluster is unrelated speculative squatting — see
  FAFA178 case study).
- The UFA/DSI case is a rare instance where this kind of domain-recon work
  connects directly to a real, ongoing law-enforcement matter — worth keeping
  in mind if any of nrdguard's future findings look like they'd be useful to
  route toward an actual reporting channel, rather than only internal
  blocklist tuning.
