# NRDGuard Daily Summary -- 2026-11-19

## Domains Scanned
- Total domains fetched: 308,413

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 617 (11 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 17,598

| Category | Count |
|---|---|
| Gambling | 14,402 |
| Scams/Phishing | 1,437 |
| Malware/C2 | 963 |
| Typosquatting | 586 |
| Ads | 70 |
| AI Deepfake/Impersonation | 57 |
| Cryptojacking | 47 |
| Tracking/Analytics | 36 |

### nemotron-3-super:cloud
- Batches processed: 617 (400 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 1,902

| Category | Count |
|---|---|
| Gambling | 1,275 |
| Ads | 392 |
| Scams/Phishing | 93 |
| Typosquatting | 58 |
| Tracking/Analytics | 36 |
| Malware/C2 | 24 |
| AI Deepfake/Impersonation | 16 |
| Cryptojacking | 8 |

## Model Agreement
- Domains flagged by at least one model: 18,137
- Domains every model agreed on (domain + category): 1,251

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| meilani.ns.cloudflare.com | 639 |
| zahir.ns.cloudflare.com | 638 |
| ns1.dyna-ns.net | 162 |
| ns2.dyna-ns.net | 162 |
| a.share-dns.com | 36 |
| b.share-dns.net | 36 |
| launch1.spaceship.net | 32 |
| launch2.spaceship.net | 32 |
| quinton.ns.cloudflare.com | 29 |
| surina.ns.cloudflare.com | 27 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,568
- Newly added: 0

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 9,144,873 domains
- Final: 9,144,873 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,479,346 domains
- Final: 6,479,346 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
