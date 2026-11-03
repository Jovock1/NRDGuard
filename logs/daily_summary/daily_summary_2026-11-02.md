# NRDGuard Daily Summary -- 2026-11-02

## Domains Scanned
- Total domains fetched: 315,139

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 631 (15 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 11,077

| Category | Count |
|---|---|
| Gambling | 8,380 |
| Scams/Phishing | 1,466 |
| Typosquatting | 612 |
| Malware/C2 | 459 |
| Ads | 68 |
| Cryptojacking | 41 |
| AI Deepfake/Impersonation | 30 |
| Tracking/Analytics | 21 |

### nemotron-3-super:cloud
- Batches processed: 631 (397 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 1,060

| Category | Count |
|---|---|
| Gambling | 447 |
| Ads | 372 |
| Scams/Phishing | 104 |
| Typosquatting | 66 |
| Malware/C2 | 29 |
| Tracking/Analytics | 27 |
| AI Deepfake/Impersonation | 9 |
| Cryptojacking | 6 |

## Model Agreement
- Domains flagged by at least one model: 11,649
- Domains every model agreed on (domain + category): 470

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| laylah.ns.cloudflare.com | 140 |
| thaddeus.ns.cloudflare.com | 140 |
| aaron.ns.cloudflare.com | 127 |
| raegan.ns.cloudflare.com | 127 |
| dns1.registrar-servers.com | 69 |
| dns2.registrar-servers.com | 69 |
| ns1.dyna-ns.net | 65 |
| ns2.dyna-ns.net | 65 |
| ns1.dnsowl.com | 51 |
| ns2.dnsowl.com | 51 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,563
- Newly added: 1

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,317,642 domains
- Final: 8,317,643 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 5,820,023 domains
- Final: 5,820,024 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
