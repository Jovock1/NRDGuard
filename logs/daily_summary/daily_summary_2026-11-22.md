# NRDGuard Daily Summary -- 2026-11-22

## Domains Scanned
- Total domains fetched: 280,978

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 562 (3 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 15,684

| Category | Count |
|---|---|
| Gambling | 13,191 |
| Scams/Phishing | 1,227 |
| Typosquatting | 611 |
| Malware/C2 | 520 |
| Ads | 52 |
| Cryptojacking | 43 |
| AI Deepfake/Impersonation | 25 |
| Tracking/Analytics | 15 |

### nemotron-3-super:cloud
- Batches processed: 562 (87 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 18,220

| Category | Count |
|---|---|
| Gambling | 10,367 |
| Scams/Phishing | 3,159 |
| Ads | 1,730 |
| Malware/C2 | 1,134 |
| Tracking/Analytics | 859 |
| Typosquatting | 800 |
| AI Deepfake/Impersonation | 109 |
| Cryptojacking | 62 |

## Model Agreement
- Domains flagged by at least one model: 25,978
- Domains every model agreed on (domain + category): 7,126

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| meilani.ns.cloudflare.com | 307 |
| zahir.ns.cloudflare.com | 307 |
| ns7.alidns.com | 61 |
| ns8.alidns.com | 61 |
| leah.ns.cloudflare.com | 54 |
| maciej.ns.cloudflare.com | 54 |
| ns1.dnsowl.com | 53 |
| ns2.dnsowl.com | 53 |
| ns3.dnsowl.com | 53 |
| launch1.spaceship.net | 48 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 0
- Newly added: 0

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 9,234,586 domains
- Final: 9,234,586 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,502,798 domains
- Final: 6,502,798 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

The ad/tracking domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
