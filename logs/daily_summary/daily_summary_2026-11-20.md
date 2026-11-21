# NRDGuard Daily Summary -- 2026-11-20

## Domains Scanned
- Total domains fetched: 439,147

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 879 (9 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 28,276

| Category | Count |
|---|---|
| Gambling | 24,433 |
| Scams/Phishing | 2,052 |
| Typosquatting | 1,144 |
| Malware/C2 | 438 |
| Ads | 66 |
| AI Deepfake/Impersonation | 59 |
| Cryptojacking | 53 |
| Tracking/Analytics | 31 |

### nemotron-3-super:cloud
- Batches processed: 879 (93 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 33,392

| Category | Count |
|---|---|
| Gambling | 25,256 |
| Scams/Phishing | 3,887 |
| Ads | 1,745 |
| Malware/C2 | 1,041 |
| Typosquatting | 686 |
| Tracking/Analytics | 475 |
| AI Deepfake/Impersonation | 203 |
| Cryptojacking | 99 |

## Model Agreement
- Domains flagged by at least one model: 45,623
- Domains every model agreed on (domain + category): 15,071

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| ns1.dyna-ns.net | 2,551 |
| ns2.dyna-ns.net | 2,551 |
| meilani.ns.cloudflare.com | 1,041 |
| zahir.ns.cloudflare.com | 1,036 |
| dns1.registrar-servers.com | 324 |
| dns2.registrar-servers.com | 324 |
| launch1.spaceship.net | 280 |
| launch2.spaceship.net | 280 |
| raegan.ns.cloudflare.com | 132 |
| aitana.ns.cloudflare.com | 132 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 0
- Newly added: 0

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 9,190,226 domains
- Final: 9,190,226 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,494,362 domains
- Final: 6,494,362 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

The ad/tracking domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
