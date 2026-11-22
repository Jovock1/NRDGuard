# NRDGuard Daily Summary -- 2026-11-21

## Domains Scanned
- Total domains fetched: 342,016

## Classification Results by Model
### gemma4:31b-cloud
- Batches processed: 685 (2 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 18,274

| Category | Count |
|---|---|
| Gambling | 13,980 |
| Scams/Phishing | 2,303 |
| Malware/C2 | 1,064 |
| Typosquatting | 714 |
| Ads | 100 |
| Cryptojacking | 50 |
| AI Deepfake/Impersonation | 34 |
| Tracking/Analytics | 29 |

### nemotron-3-super:cloud
- Batches processed: 685 (398 returned zero flagged domains, 0 failed and were skipped)
- Total flagged: 2,051

| Category | Count |
|---|---|
| Gambling | 1,366 |
| Ads | 300 |
| Scams/Phishing | 155 |
| Typosquatting | 152 |
| Malware/C2 | 36 |
| Tracking/Analytics | 28 |
| AI Deepfake/Impersonation | 12 |
| Cryptojacking | 2 |

## Model Agreement
- Domains flagged by at least one model: 18,838
- Domains every model agreed on (domain + category): 1,385

## Top Nameservers This Run
Nameservers hosting 2+ of today's flagged domains -- often a sign of one operator's infrastructure rather than independent registrations.

| Nameserver | Flagged Domains |
|---|---|
| meilani.ns.cloudflare.com | 161 |
| zahir.ns.cloudflare.com | 161 |
| ns1.dyna-ns.net | 99 |
| ns2.dyna-ns.net | 99 |
| launch1.spaceship.net | 60 |
| launch2.spaceship.net | 60 |
| ns15.abovedomains.com | 55 |
| ns16.abovedomains.com | 55 |
| ns1.dnsowl.com | 47 |
| ns2.dnsowl.com | 47 |

## Compromised Domains Feed
- Domains fetched: 0
- Newly added: 0

## Ad/Tracking Domains Feed
- Domains fetched: 0
- Newly added: 0

## List 1 -- blocklist.txt (union of all models + Compromised Domains + Ad/Tracking Domains)
- After classification: 9,208,843 domains
- Final: 9,208,843 domains

## List 2 -- blocklist_consensus.txt (model agreement + Compromised Domains + Ad/Tracking Domains)
- After classification: 6,495,740 domains
- Final: 6,495,740 domains

## Allowlist
- Domains suppressed: 0

## Pruning
- Dormant domains removed (classification-only, not re-flagged or confirmed by a known list in over 180 days): 0

## Note
The compromised domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

The ad/tracking domains fetch failed for this run (see the run's log) and was skipped rather than aborting the whole pipeline -- nothing was merged in from that source this time. Re-run that step for this date once the feed is reachable again.

Dormant-domain pruning was skipped for this run because a known-list fetch failed above -- pruning needs a complete, up-to-date view of every known-list domain to safely tell a dead campaign apart from one a source still confirms.
