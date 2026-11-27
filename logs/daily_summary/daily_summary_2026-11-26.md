# NRDGuard Daily Summary -- 2026-11-26

## Domains Scanned
- Total domains fetched: 392,301

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 785 (19 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 20,238

| Category | Count |
|---|---|
| Gambling | 16,106 |
| Scams/Phishing | 2,324 |
| Typosquatting | 805 |
| Malware/C2 | 693 |
| Ads | 128 |
| AI Deepfake/Impersonation | 97 |
| Cryptojacking | 51 |
| Tracking/Analytics | 34 |

### nemotron-3-super:cloud
- Batches processed: 785 (448 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 2,034

| Category | Count |
|---|---|
| Gambling | 1,277 |
| Ads | 468 |
| Scams/Phishing | 163 |
| Typosquatting | 64 |
| Malware/C2 | 30 |
| AI Deepfake/Impersonation | 16 |
| Tracking/Analytics | 14 |
| Cryptojacking | 2 |

## Model Agreement
- Domains flagged by at least one model: 20,970
- Domains every model agreed on (domain + category): 1,243

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| ns1.dyna-ns.net | 342 |
| ns2.dyna-ns.net | 342 |
| meilani.ns.cloudflare.com | 115 |
| zahir.ns.cloudflare.com | 114 |
| raegan.ns.cloudflare.com | 69 |
| aaron.ns.cloudflare.com | 67 |
| elliott.ns.cloudflare.com | 53 |
| lilith.ns.cloudflare.com | 52 |
| malavika.ns.cloudflare.com | 42 |
| corey.ns.cloudflare.com | 41 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 3,560
- Newly added: 3

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 9,626,572 domains
- Final: 9,626,575 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,907,193 domains
- Final: 6,907,196 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
