# IOCs

| Indicator | Type | Notes |
|---|---|---|
| `T1796401078D050ED3E05D43A6BD172D5C0F0A7B48C5C63AFF61661FCBBA186269D8E4AE` | TLSH | FakeCaptcha PDF structural fingerprint; over 12,700 similar PDFs (fuzzy structural match) |
| `9a448a3f5689bff73158220126cca1085` | vhash | 2026 PDF cluster; exact structural match, ~2,480 files across both clusters |
| `9cacf340f36958ada8f48cd21217732cf` | vhash | 2025 PDF cluster; exact structural match |
| `dutabuz[.]com`, `zuwufag[.]com` | Lure domains | 2025 pool; Namecheap; 80+ DGA subdomains each |
| `nurepikis[.]com`, `tugoduzak[.]com`, `maxudijuz[.]com`, `pofezaf[.]com`, `godoxevez[.]com`, `vimemug[.]com`, `jufewine[.]com`, `binonelola[.]com`, `bovetewa[.]com`, `riwitamo[.]com`, `gowixese[.]com` | Lure domains | 2026 pool; 2025 intermediaries reused as lure entries. `binonelola[.]com` is also contacted by the Injuke dropper below |
| `berapt-medii[.]com` | Stage-2 / Malware Distribution Point | Legion Loader "Content Keeper" hub; confirmed in Netskope telemetry via referer pivot from 2025 lures |
| `yfdpco1[.]com`, `yfdpco4[.]com`, `yfdpco2[.]com` | Stage-2 / TDS gate | `sk-park[.]php` gate; shared hub |
| `scorenetsystems[.]pro`, `chromovira[.]org`, `solidlinkpro[.]info` | Scam domains | Premium-SMS subscription trap; QR "verify with mobile" on landing page |
| `sms:797079&body=ALTA 441` | Premium-SMS indicator | "ALTA 441" to shortcode 797079 (Spanish premium-rate) |
| `87b8b76762eac941c562c6c8eefb8402f48fc70fcfe360a274b12e75dd5726e2` | SHA256 | `Documentos[.]pdf.exe`, 191 MB WinRAR SFX Injuke dropper, Spanish UI; VT submission |
| `212.92.104[.]119` | IP | TDS entry gate (NFORCE, NL) |
| `185.53.179[.]200` | IP | `ww80` traffic router (Team Internet) |
| `208.91.196[.]46` | IP | `yfdpco` gate backend (Confluence Networks) |
| `188.72.236[.]249` | IP | `berapt-medii[.]com` Legion Loader hub; verified via VirusTotal |

## External references

Unit42 documentated 2025 cluster: https://x.com/Unit42_Intel/status/1906820885865988184.