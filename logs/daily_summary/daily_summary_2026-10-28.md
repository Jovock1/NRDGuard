# NRDGuard Daily Summary -- 2026-10-28

## Domains Scanned
- Total domains fetched: 413,734

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 828 (16 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 16,032

| Category | Count |
|---|---|
| Gambling | 11,800 |
| Scams/Phishing | 2,603 |
| Typosquatting | 828 |
| Malware/C2 | 304 |
| Cryptojacking | 211 |
| AI Deepfake/Impersonation | 200 |
| Ads | 59 |
| Tracking/Analytics | 27 |

### nemotron-3-super:cloud
- Batches processed: 828 (494 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 1,227

| Category | Count |
|---|---|
| Gambling | 826 |
| Scams/Phishing | 117 |
| Ads | 114 |
| Tracking/Analytics | 63 |
| Typosquatting | 53 |
| Malware/C2 | 28 |
| AI Deepfake/Impersonation | 24 |
| Cryptojacking | 2 |

## Model Agreement
- Domains flagged by at least one model: 16,420
- Domains every model agreed on (domain + category): 769

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| thaddeus.ns.cloudflare.com | 150 |
| laylah.ns.cloudflare.com | 148 |
| mary.ns.cloudflare.com | 120 |
| dns1.registrar-servers.com | 119 |
| dns2.registrar-servers.com | 119 |
| ram.ns.cloudflare.com | 119 |
| ns1.dnsowl.com | 54 |
| ns2.dnsowl.com | 54 |
| ns3.dnsowl.com | 54 |
| launch1.spaceship.net | 51 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,567
- Newly added: 4

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,174,393 domains
- Final: 8,174,397 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 5,721,894 domains
- Final: 5,721,898 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
