# NRDGuard Daily Summary -- 2026-11-01

## Domains Scanned
- Total domains fetched: 265,229

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 531 (6 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 10,797

| Category | Count |
|---|---|
| Gambling | 8,179 |
| Scams/Phishing | 1,338 |
| Typosquatting | 611 |
| Malware/C2 | 434 |
| Ads | 103 |
| Tracking/Analytics | 56 |
| Cryptojacking | 46 |
| AI Deepfake/Impersonation | 30 |

### nemotron-3-super:cloud
- Batches processed: 531 (336 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 713

| Category | Count |
|---|---|
| Gambling | 496 |
| Ads | 85 |
| Scams/Phishing | 74 |
| Typosquatting | 21 |
| Tracking/Analytics | 19 |
| Malware/C2 | 11 |
| AI Deepfake/Impersonation | 6 |
| Cryptojacking | 1 |

## Model Agreement
- Domains flagged by at least one model: 11,013
- Domains every model agreed on (domain + category): 452

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| ns1.dyna-ns.net | 173 |
| ns2.dyna-ns.net | 173 |
| dns1.registrar-servers.com | 60 |
| dns2.registrar-servers.com | 60 |
| ns1.domainnamens.com | 49 |
| ns2.domainnamens.com | 49 |
| nelly.ns.cloudflare.com | 39 |
| hasslo.ns.cloudflare.com | 36 |
| dns1.namecheaphosting.com | 36 |
| dns2.namecheaphosting.com | 36 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,562
- Newly added: 0

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,306,083 domains
- Final: 8,306,083 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 5,819,554 domains
- Final: 5,819,554 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
