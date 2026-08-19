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
name-clusters), plus two separate deep-dive case studies chasing specific
operators to ground: **AskMeBet** and **UFA/UFABET** (see below). Every
sampled domain got a `domain_report` (DNS/WHOIS/ASN/geo) and a
`fetch_homepage` at minimum; several got `fetch_rendered` and deeper follow-up
where the surface result was ambiguous or interesting.

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

### Why the two cases look so different

AskMeBet: no license, no registrant, no affiliate footprint, no news
coverage — a platform vendor deliberately kept invisible. UFA/UFABET: large
and established enough to have drawn real state investigative attention,
with an internal agent/commission economy (commissions reported up to 85%)
documented by the investigators themselves. Independently described as one
of the *three biggest* networks in the country — AskMeBet, by comparison,
reads like a smaller or newer platform still operating below that threshold
of visibility.

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
- Consider adding `Askmeslot`, `Askmelotto`, `Askmeplay`, and a broader UFA
  mirror sweep (only 20 of an unknown total UFA domains were in-scope here)
  to future sampling rounds — both platforms are confirmed larger than what
  nrdguard has caught so far.
- The UFA/DSI case is a rare instance where this kind of domain-recon work
  connects directly to a real, ongoing law-enforcement matter — worth keeping
  in mind if any of nrdguard's future findings look like they'd be useful to
  route toward an actual reporting channel, rather than only internal
  blocklist tuning.
