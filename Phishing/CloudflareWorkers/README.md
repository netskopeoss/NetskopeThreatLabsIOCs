# Phishing with Cloudflare Workers: Transparent Phishing and HTML smuggling

Netskope Threat Labs is tracking multiple phishing campaigns that abuse Cloudflare Workers. The campaigns are likely the work of different attackers since they use two very different techniques. One campaign (similar to the previously disclosed Azorult campaign) uses HTML smuggling, a detection evasion technique often used for downloading malware, to hide the phishing content from network inspection. The other uses a method that we call transparent phishing: The attacker uses Cloudflare Workers to act as a reverse proxy server for a legitimate login page, intercepting traffic between the victim and the login page to capture credentials, cookies, and tokens.  

### IOCs
* **README.md**: All IOCs from this phishing campaign analyzed by Netskope Threat Labs.
