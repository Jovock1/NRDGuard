# NRDGuard Daily Summary -- 2026-11-14

## Domains Scanned
- Total domains fetched: 310,908

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 622 (8 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 15,134

| Category | Count |
|---|---|
| Gambling | 12,012 |
| Scams/Phishing | 1,373 |
| Malware/C2 | 866 |
| Typosquatting | 746 |
| AI Deepfake/Impersonation | 51 |
| Cryptojacking | 35 |
| Ads | 28 |
| Tracking/Analytics | 23 |

### nemotron-3-super:cloud
- Batches processed: 622 (378 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 1,450

| Category | Count |
|---|---|
| Gambling | 1,152 |
| Typosquatting | 128 |
| Ads | 63 |
| Scams/Phishing | 63 |
| Tracking/Analytics | 17 |
| Malware/C2 | 13 |
| AI Deepfake/Impersonation | 12 |
| Cryptojacking | 2 |

## Model Agreement
- Domains flagged by at least one model: 15,485
- Domains every model agreed on (domain + category): 1,080

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| ns1.dyna-ns.net | 246 |
| ns2.dyna-ns.net | 246 |
| mary.ns.cloudflare.com | 80 |
| ram.ns.cloudflare.com | 79 |
| launch1.spaceship.net | 51 |
| launch2.spaceship.net | 51 |
| dns1.registrar-servers.com | 47 |
| dns2.registrar-servers.com | 47 |
| laylah.ns.cloudflare.com | 40 |
| thaddeus.ns.cloudflare.com | 40 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,564
- Newly added: 2

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,793,729 domains
- Final: 8,793,731 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,176,195 domains
- Final: 6,176,197 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
