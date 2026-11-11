# NRDGuard Daily Summary -- 2026-11-10

## Domains Scanned
- Total domains fetched: 305,113

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 611 (5 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 13,689

| Category | Count |
|---|---|
| Gambling | 10,184 |
| Scams/Phishing | 2,106 |
| Typosquatting | 680 |
| Malware/C2 | 527 |
| AI Deepfake/Impersonation | 63 |
| Ads | 59 |
| Cryptojacking | 47 |
| Tracking/Analytics | 23 |

### nemotron-3-super:cloud
- Batches processed: 611 (373 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 1,173

| Category | Count |
|---|---|
| Gambling | 731 |
| Scams/Phishing | 209 |
| Typosquatting | 123 |
| Ads | 41 |
| Malware/C2 | 35 |
| Tracking/Analytics | 22 |
| AI Deepfake/Impersonation | 10 |
| Cryptojacking | 2 |

## Model Agreement
- Domains flagged by at least one model: 14,002
- Domains every model agreed on (domain + category): 842

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| ns1.dyna-ns.net | 242 |
| ns2.dyna-ns.net | 242 |
| lina.ns.cloudflare.com | 112 |
| darwin.ns.cloudflare.com | 111 |
| johnny.ns.cloudflare.com | 79 |
| fatima.ns.cloudflare.com | 76 |
| a.share-dns.com | 67 |
| b.share-dns.net | 67 |
| launch1.spaceship.net | 46 |
| launch2.spaceship.net | 46 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,561
- Newly added: 1

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,682,655 domains
- Final: 8,682,656 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,103,030 domains
- Final: 6,103,031 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
