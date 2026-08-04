# FakeCaptcha PDF TDS

Netskope Threat Labs is tracking a Traffic Distribution System (TDS) campaign that uses fake CAPTCHA PDF lures to funnel victims through a multi-stage pipeline: SEO-poisoned PDF documents with fake CAPTCHA verifiers, a TDS gate that routes traffic to scam or malware-distribution endpoints, premium-SMS subscription traps, and ultimately Legion Loader / Injuke dropper delivery. The campaign operates across two PDF clusters (2025 and 2026) identified by shared structural fingerprints (TLSH/vhash), with lure domains registered via Namecheap and rotated through DGA-style subdomains.

## Campaign Flow
- User searches Google (or AI assistant) → clicks poisoned result → browser downloads PDF from Webflow CDN
- CDN URL pattern: `<cdn>/<webflow-site-id>/<file-id>_<random-syllables>.pdf`
- PDF displays "I'm not a bot" FakeCaptcha lure image; user clicks image → redirected to TDS entry point (e.g. dutabuz.com or zuwufag.com subdomain)
- TDS gate:
    - layer 1: IP/ASN check — datacenter/cloud IPs receive TLS fatal alert (confirmed via Burp); residential/corporate IPs proceed
    - layer 2: JS challenge (Joken JWT "js":1, Elixir/Phoenix) — bots rejected; real browsers proceed
    - layer 3: ww80.dutabuz.com traffic router (Team Internet/Trellian ww80 platform — a third-party TDS/parking hop, not the operator's own stack) — geo/device filtering; non-qualifying traffic → ad lander
- Stage-2 payload hosts: zuwufag.com / dutabuz.com TDS routes victims to — berapt-medii.com (Malware Distribution Point, referer_domain)  -> Final payload: Legion Loader.

## IOCs

- README.md: All IOCs from this FakeCaptcha PDF TDS campaign analyzed by Netskope Threat Labs.
