# NRDGuard Daily Summary -- 2026-10-29

## Domains Scanned
- Total domains fetched: 455,907

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 912 (6 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 16,099

| Category | Count |
|---|---|
| Gambling | 10,962 |
| Scams/Phishing | 2,830 |
| Malware/C2 | 1,016 |
| Typosquatting | 1,000 |
| Ads | 108 |
| AI Deepfake/Impersonation | 88 |
| Cryptojacking | 56 |
| Tracking/Analytics | 39 |

### nemotron-3-super:cloud
- Batches processed: 912 (555 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 1,317

| Category | Count |
|---|---|
| Gambling | 925 |
| Scams/Phishing | 184 |
| Ads | 79 |
| Malware/C2 | 48 |
| Typosquatting | 44 |
| Tracking/Analytics | 17 |
| AI Deepfake/Impersonation | 15 |
| Cryptojacking | 5 |

## Model Agreement
- Domains flagged by at least one model: 16,470
- Domains every model agreed on (domain + category): 908

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| ns1.dyna-ns.net | 419 |
| ns2.dyna-ns.net | 419 |
| rick.ns.cloudflare.com | 49 |
| pam.ns.cloudflare.com | 48 |
| dns1.registrar-servers.com | 48 |
| dns2.registrar-servers.com | 48 |
| ns1.dnsowl.com | 37 |
| ns2.dnsowl.com | 37 |
| ns3.dnsowl.com | 37 |
| launch1.spaceship.net | 33 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,569
- Newly added: 2

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,190,480 domains
- Final: 8,190,482 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 5,722,790 domains
- Final: 5,722,792 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
