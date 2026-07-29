What is NRDGuard the TL;DR:

  It is a list of domains that have been marked as Scam, Gambling, Typoquatting, Malware, Ads, Tracking, Cryptojacking, and AI Deepfake impersonations.

  It is designed to be read by PI-Hole to block these sites on your network. Simply add a new list to PI-Hole that points to
  https://media.githubusercontent.com/media/Jovock1/NRDGuard/refs/heads/main/blocklist.txt and you are good to go.

  There are two lists available:
  - blocklist.txt -- broader coverage. A domain is included if ANY AI model flags it.
  - blocklist_consensus.txt -- stricter, fewer false positives. A domain is only included if ALL AI models agree on both the domain and its category. Available at
    https://media.githubusercontent.com/media/Jovock1/NRDGuard/refs/heads/main/blocklist_consensus.txt

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
 
  The agent, downloads 2 lists. The first list is a list of confirmed websites known for malware. These get added to both blocklist.txt and blocklist_consensus.txt, no questions asked.

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

Logs:
  When a domain is added to blocklists.txt a log is created to try and determine how, when, and why it was added. This is created in both csv and json formats. 
  These can be found in the logs/csv and logs/json folders respectively

  The compromised log keeps track of the domains that have been pre-confirmed as malware. The

  The flagged domains log keeps track of the domains that the AI has determined to be malicious, the exact catagory the domain falls into, and which model flagged it.

  Starting on 7/10, a new log will be kept called daily summary. This is a high level log of the number of domains that fell into each catagory every day.

Security:
  Both blocklist.txt and blocklist_consensus.txt, and the logs, all have been hashed into sha256. This gives you the ability to confirm if the blocklists and/or logs have been tampared with.
  
