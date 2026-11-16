# NRDGuard Daily Summary -- 2026-11-15

## Domains Scanned
- Total domains fetched: 367,870

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 736 (4 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 15,337

| Category | Count |
|---|---|
| Gambling | 11,312 |
| Scams/Phishing | 2,079 |
| Typosquatting | 1,063 |
| Malware/C2 | 670 |
| AI Deepfake/Impersonation | 69 |
| Ads | 60 |
| Cryptojacking | 55 |
| Tracking/Analytics | 29 |

### nemotron-3-super:cloud
- Batches processed: 736 (436 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 1,914

| Category | Count |
|---|---|
| Gambling | 1,398 |
| Ads | 281 |
| Scams/Phishing | 102 |
| Malware/C2 | 62 |
| Typosquatting | 36 |
| Tracking/Analytics | 18 |
| AI Deepfake/Impersonation | 14 |
| Cryptojacking | 3 |

## Model Agreement
- Domains flagged by at least one model: 16,061
- Domains every model agreed on (domain + category): 1,155

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| ns1.dyna-ns.net | 156 |
| ns2.dyna-ns.net | 156 |
| dns1.registrar-servers.com | 81 |
| dns2.registrar-servers.com | 81 |
| ram.ns.cloudflare.com | 56 |
| arely.ns.cloudflare.com | 54 |
| jerome.ns.cloudflare.com | 52 |
| carmelo.ns.cloudflare.com | 49 |
| launch1.spaceship.net | 49 |
| launch2.spaceship.net | 49 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,564
- Newly added: 0

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,809,683 domains
- Final: 8,809,683 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,177,350 domains
- Final: 6,177,350 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
