# NRDGuard Daily Summary -- 2026-11-12

## Domains Scanned
- Total domains fetched: 360,019

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 721 (5 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 14,302

| Category | Count |
|---|---|
| Gambling | 10,731 |
| Scams/Phishing | 1,785 |
| Typosquatting | 875 |
| Malware/C2 | 676 |
| AI Deepfake/Impersonation | 94 |
| Cryptojacking | 69 |
| Ads | 39 |
| Tracking/Analytics | 33 |

### nemotron-3-super:cloud
- Batches processed: 721 (421 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 2,266

| Category | Count |
|---|---|
| Gambling | 1,631 |
| Scams/Phishing | 243 |
| Ads | 176 |
| Typosquatting | 103 |
| Tracking/Analytics | 40 |
| Malware/C2 | 39 |
| Cryptojacking | 27 |
| AI Deepfake/Impersonation | 7 |

## Model Agreement
- Domains flagged by at least one model: 14,899
- Domains every model agreed on (domain + category): 1,443

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| ns1.dyna-ns.net | 362 |
| ns2.dyna-ns.net | 362 |
| dns1.registrar-servers.com | 88 |
| dns2.registrar-servers.com | 88 |
| curitiba.ns.porkbun.com | 62 |
| fortaleza.ns.porkbun.com | 62 |
| maceio.ns.porkbun.com | 62 |
| salvador.ns.porkbun.com | 62 |
| launch1.spaceship.net | 34 |
| launch2.spaceship.net | 34 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,563
- Newly added: 2

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,697,453 domains
- Final: 8,697,455 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,104,471 domains
- Final: 6,104,473 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
