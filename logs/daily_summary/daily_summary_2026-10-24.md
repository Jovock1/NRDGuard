# NRDGuard Daily Summary -- 2026-10-24

## Domains Scanned
- Total domains fetched: 454,939

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 910 (11 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 15,842

| Category | Count |
|---|---|
| Gambling | 10,851 |
| Scams/Phishing | 2,713 |
| Typosquatting | 755 |
| Malware/C2 | 708 |
| Cryptojacking | 524 |
| Ads | 155 |
| AI Deepfake/Impersonation | 97 |
| Tracking/Analytics | 39 |

### nemotron-3-super:cloud
- Batches processed: 910 (583 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 1,766

| Category | Count |
|---|---|
| Gambling | 729 |
| Ads | 346 |
| Scams/Phishing | 330 |
| Tracking/Analytics | 222 |
| Malware/C2 | 65 |
| Typosquatting | 38 |
| Cryptojacking | 25 |
| AI Deepfake/Impersonation | 11 |

## Model Agreement
- Domains flagged by at least one model: 16,911
- Domains every model agreed on (domain + category): 643

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| launch1.spaceship.net | 70 |
| launch2.spaceship.net | 70 |
| dns1.registrar-servers.com | 43 |
| dns2.registrar-servers.com | 43 |
| ns59.domaincontrol.com | 42 |
| ns60.domaincontrol.com | 42 |
| n1.xundns.com | 39 |
| n2.xundns.com | 39 |
| ns25.domaincontrol.com | 35 |
| ns26.domaincontrol.com | 35 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,563
- Newly added: 0

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 7,718,459 domains
- Final: 7,718,459 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 5,243,691 domains
- Final: 5,243,691 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
