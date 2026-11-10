# NRDGuard Daily Summary -- 2026-11-09

## Domains Scanned
- Total domains fetched: 276,227

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 553 (3 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 9,814

| Category | Count |
|---|---|
| Gambling | 7,180 |
| Scams/Phishing | 1,336 |
| Typosquatting | 693 |
| Malware/C2 | 451 |
| Ads | 55 |
| Cryptojacking | 52 |
| AI Deepfake/Impersonation | 25 |
| Tracking/Analytics | 22 |

### nemotron-3-super:cloud
- Batches processed: 553 (339 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 703

| Category | Count |
|---|---|
| Gambling | 489 |
| Scams/Phishing | 104 |
| Ads | 41 |
| Typosquatting | 37 |
| Malware/C2 | 14 |
| Tracking/Analytics | 11 |
| AI Deepfake/Impersonation | 4 |
| Cryptojacking | 3 |

## Model Agreement
- Domains flagged by at least one model: 9,978
- Domains every model agreed on (domain + category): 512

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| launch1.spaceship.net | 135 |
| launch2.spaceship.net | 135 |
| ns1.atomregistrar.com | 105 |
| ns2.atomregistrar.com | 105 |
| ns1.dyna-ns.net | 63 |
| ns2.dyna-ns.net | 63 |
| ns1.dnsowl.com | 51 |
| ns2.dnsowl.com | 51 |
| ns3.dnsowl.com | 51 |
| dns1.registrar-servers.com | 50 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,560
- Newly added: 0

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,595,632 domains
- Final: 8,595,632 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,022,581 domains
- Final: 6,022,581 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
