# NRDGuard Daily Summary -- 2026-11-05

## Domains Scanned
- Total domains fetched: 312,675

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 626 (14 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 10,984

| Category | Count |
|---|---|
| Gambling | 7,807 |
| Scams/Phishing | 1,857 |
| Typosquatting | 723 |
| Malware/C2 | 393 |
| AI Deepfake/Impersonation | 55 |
| Ads | 52 |
| Tracking/Analytics | 52 |
| Cryptojacking | 45 |

### nemotron-3-super:cloud
- Batches processed: 626 (387 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 937

| Category | Count |
|---|---|
| Gambling | 658 |
| Ads | 87 |
| Scams/Phishing | 79 |
| Malware/C2 | 32 |
| Typosquatting | 32 |
| Tracking/Analytics | 25 |
| AI Deepfake/Impersonation | 21 |
| Cryptojacking | 3 |

## Model Agreement
- Domains flagged by at least one model: 11,241
- Domains every model agreed on (domain + category): 654

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| dns1.registrar-servers.com | 96 |
| dns2.registrar-servers.com | 96 |
| corey.ns.cloudflare.com | 73 |
| malavika.ns.cloudflare.com | 71 |
| ns1.dyna-ns.net | 51 |
| ns2.dyna-ns.net | 51 |
| ns1.dnsowl.com | 45 |
| ns2.dnsowl.com | 45 |
| ns3.dnsowl.com | 45 |
| adaline.ns.cloudflare.com | 37 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,564
- Newly added: 1

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 8,420,085 domains
- Final: 8,420,086 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 5,898,753 domains
- Final: 5,898,754 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
