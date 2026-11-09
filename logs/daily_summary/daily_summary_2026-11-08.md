# NRDGuard Daily Summary -- 2026-11-08

## Domains Scanned
- Total domains fetched: 448,731

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 898 (56 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 14,648

| Category | Count |
|---|---|
| Gambling | 11,999 |
| Scams/Phishing | 1,543 |
| Typosquatting | 642 |
| Malware/C2 | 272 |
| Cryptojacking | 65 |
| Ads | 55 |
| AI Deepfake/Impersonation | 48 |
| Tracking/Analytics | 24 |

### nemotron-3-super:cloud
- Batches processed: 898 (457 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 4,928

| Category | Count |
|---|---|
| Gambling | 3,116 |
| Scams/Phishing | 610 |
| Malware/C2 | 497 |
| Ads | 444 |
| Typosquatting | 134 |
| Tracking/Analytics | 71 |
| AI Deepfake/Impersonation | 38 |
| Cryptojacking | 18 |

## Model Agreement
- Domains flagged by at least one model: 17,335
- Domains every model agreed on (domain + category): 2,005

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| ns1.dyna-ns.net | 295 |
| ns2.dyna-ns.net | 295 |
| dns1.registrar-servers.com | 154 |
| dns2.registrar-servers.com | 154 |
| aaden.ns.cloudflare.com | 113 |
| grannbo.ns.cloudflare.com | 113 |
| nelly.ns.cloudflare.com | 65 |
| launch1.spaceship.net | 64 |
| launch2.spaceship.net | 64 |
| lennon.ns.cloudflare.com | 59 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 0
- Newly added: 0

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,585,746 domains
- Final: 8,585,746 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,022,073 domains
- Final: 6,022,073 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

The ad/tracking domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
