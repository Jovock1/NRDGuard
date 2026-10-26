# NRDGuard Daily Summary -- 2026-10-23

## Domains Scanned
- Total domains fetched: 342,099

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 685 (2 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 15,092

| Category | Count |
|---|---|
| Gambling | 11,478 |
| Scams/Phishing | 1,728 |
| Typosquatting | 999 |
| Malware/C2 | 683 |
| AI Deepfake/Impersonation | 75 |
| Ads | 71 |
| Cryptojacking | 41 |
| Tracking/Analytics | 17 |

### nemotron-3-super:cloud
- Batches processed: 685 (407 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 1,105

| Category | Count |
|---|---|
| Gambling | 646 |
| Scams/Phishing | 166 |
| Ads | 163 |
| Tracking/Analytics | 45 |
| Typosquatting | 41 |
| Malware/C2 | 28 |
| AI Deepfake/Impersonation | 12 |
| Cryptojacking | 4 |

## Model Agreement
- Domains flagged by at least one model: 15,537
- Domains every model agreed on (domain + category): 622

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| mary.ns.cloudflare.com | 112 |
| ram.ns.cloudflare.com | 98 |
| ophelia.ns.cloudflare.com | 96 |
| jarred.ns.cloudflare.com | 96 |
| nancy.ns.cloudflare.com | 96 |
| tom.ns.cloudflare.com | 95 |
| ns1.dyna-ns.net | 49 |
| ns2.dyna-ns.net | 49 |
| launch1.spaceship.net | 42 |
| launch2.spaceship.net | 42 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,563
- Newly added: 2

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 7,701,668 domains
- Final: 7,701,670 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 5,243,049 domains
- Final: 5,243,051 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
