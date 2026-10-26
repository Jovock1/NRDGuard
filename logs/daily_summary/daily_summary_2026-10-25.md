# NRDGuard Daily Summary -- 2026-10-25

## Domains Scanned
- Total domains fetched: 432,122

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 865 (6 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 17,036

| Category | Count |
|---|---|
| Gambling | 12,557 |
| Scams/Phishing | 2,305 |
| Typosquatting | 856 |
| Malware/C2 | 769 |
| Ads | 232 |
| Cryptojacking | 162 |
| AI Deepfake/Impersonation | 122 |
| Tracking/Analytics | 33 |

### nemotron-3-super:cloud
- Batches processed: 865 (512 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 1,800

| Category | Count |
|---|---|
| Gambling | 1,330 |
| Scams/Phishing | 162 |
| Ads | 151 |
| Typosquatting | 82 |
| Malware/C2 | 35 |
| Tracking/Analytics | 20 |
| Cryptojacking | 11 |
| AI Deepfake/Impersonation | 9 |

## Model Agreement
- Domains flagged by at least one model: 17,600
- Domains every model agreed on (domain + category): 1,151

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| raegan.ns.cloudflare.com | 205 |
| aaron.ns.cloudflare.com | 204 |
| ns1.dnsowl.com | 202 |
| ns2.dnsowl.com | 202 |
| ns3.dnsowl.com | 202 |
| dns1.registrar-servers.com | 98 |
| dns2.registrar-servers.com | 98 |
| ns1.dyna-ns.net | 94 |
| ns2.dyna-ns.net | 94 |
| launch1.spaceship.net | 80 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,563
- Newly added: 0

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 7,735,284 domains
- Final: 7,735,284 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 5,244,774 domains
- Final: 5,244,774 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
