What is NRDGuard the TL;DR:

  It is a list of domains that have been marked as Scam, Gambling, Typoquatting, Malware, Ads, Tracking, Cryptojacking, and AI Deepfake impersonations.

  It is designed to be read by PI-Hole to block these sites on your network. Simply add a new list to PI-Hole that points to
  https://github.com/Jovock1/NRDGuard/releases/download/blocklist-latest/blocklist.txt and you are good to go.

  There are two lists available:
  - blocklist.txt -- broader coverage. A domain is included if ANY AI model flags it.
  - blocklist_consensus.txt -- stricter, fewer false positives. A domain is only included if ALL AI models agree on both the domain and its category. Available at
    https://github.com/Jovock1/NRDGuard/releases/download/blocklist-latest/blocklist_consensus.txt

  NOTE: these URLs changed (previously served via Git LFS/media.githubusercontent.com). blocklist.txt and
  blocklist_consensus.txt are now published as assets on a single persistent "blocklist-latest" release,
  replaced every run, rather than committed to git -- each was a full-file rewrite every day, and Git LFS
  has no delta compression between versions, so committing them daily cost far more storage than their
  actual size would suggest. If you set up Pi-hole before this change, update the list URL to the new one
  above.

  This list is updated daily, so you have the newest threats blocked. 
  
  DISCLAMIER: The list is about 24 hours behind once a domain is created.

  DISCLAIMER: This list is provided on a best-effort basis. Domain classification is performed by AI and we do
  not guarantee that all malicious, scam, or otherwise unwanted domains are caught, nor that every domain on
  the list is correctly categorized. Use this blocklist as one layer of protection, not a sole safeguard.

  LEGAL DISCLAIMER: This project, its blocklist, and its logs are provided "AS IS", without warranty of any
  kind, express or implied, including but not limited to warranties of merchantability, fitness for a
  particular purpose, and non-infringement. Use of this project is entirely at your own risk. In no event
  shall the author(s) or contributors be liable for any claim, damages, or other liability, whether in an
  action of contract, tort, or otherwise, arising from, out of, or in connection with the project or the use
  or other dealings in the project.

The Details:
 
  The agent downloads 3 lists. The first list is a list of confirmed websites known for malware. These get added to both blocklist.txt and blocklist_consensus.txt, no questions asked.

  The third list is a known/curated list of ad and tracking servers (Peter Lowe's ad server list), entirely outside the AI scan below -- same as the malware list, these get added to both blocklist.txt and blocklist_consensus.txt, no questions asked.

  The second list is a list of all the newly created domains in the past 24 hours. Multiple AI models independently scan the names to try and determine if the name matches one of the following catagories:
  Scam
  Gambling
  Typoquatting
  Malware
  Ads
  Tracking
  Cryptojacking
  AI Deepfake impersonations

  If ANY model determines the name matches one of these catagories, then it goes to blocklist.txt. If ALL models agree on the same domain and the same catagory, it also goes to blocklist_consensus.txt -- the idea being that requiring agreement across independent models filters out one-off hallucinations from a single model.

Allowlist:
  allowlist.txt (one domain per line) is a manually-curated override for false positives. Any domain listed
  there is removed from both blocklist.txt and blocklist_consensus.txt every run -- including a domain a past
  run already blocked, not just future ones. It's still visible in that day's flagged-domains log either way;
  the allowlist only affects what actually ends up in the blocklists, not the historical record of what was
  flagged and why.

Pruning:
  A domain that was only ever flagged by our own AI classification (never confirmed by the compromised-domains
  feed or the ad/tracking list) and hasn't been re-flagged or re-confirmed in over 180 days is treated as a
  dead/abandoned campaign and removed from both blocklists. Domains sourced from the compromised feed or ad
  list are never pruned this way. Every run logs which domains it pruned to logs/csv/pruned_domains_<date>.csv.

Logs:
  When a domain is added to the blocklists a log is created to try and determine how, when, and why it was
  added. These are CSV files under logs/csv. (A classification run also writes a JSON sidecar for its own
  --resume bookkeeping under logs/json -- that one's an internal implementation detail, not a human-facing log.)

  The compromised log keeps track of the domains that have been pre-confirmed as malware. The

  The flagged domains log keeps track of the domains that the AI has determined to be malicious, the exact catagory the domain falls into, and which model flagged it.

  Starting on 7/10, a new log will be kept called daily summary. This is a high level log of the number of domains that fell into each catagory every day.

Security:
  Both blocklist.txt and blocklist_consensus.txt, and the logs, all have been hashed into sha256. This gives you the ability to confirm if the blocklists and/or logs have been tampared with.
  
