# Fake CAPTCHAs, Malicious PDFs, SEO Traps Being Leveraged for User Manual Searches

On February 12, 2025, Netskope Threat Labs reported a widespread phishing campaign using fake CAPTCHA images via Webflow CDN to trick victims searching for PDF documents on search engines. These PDF files lead to phishing sites designed to pilfer victims’ credit card and personal information. As we hunted for similar phishing campaigns, we discovered many more phishing PDF files with fake CAPTCHAs distributed across multiple domains. 

We found 260 unique domains hosting nearly 5,000 phishing PDF files that redirect victims to malicious websites. The attacker uses SEO to trick victims into visiting the pages by clicking on malicious search engine results. While most phishing pages focus on stealing credit card information, some PDF files contain fake CAPTCHAs that trick victims into executing malicious PowerShell commands, ultimately leading to the Lumma Stealer malware.

### IOCs
* **README.md**: All IOCs from this phishing campaign analyzed by Netskope Threat Labs.
