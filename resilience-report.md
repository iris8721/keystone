# Resilience Report: High-Abuse Digital-Goods Storefront + License Server

Scope: a small operation facing an adversary who files abuse/DMCA complaints, DDoSes, and attempts operator identification. Baseline: single-node k3s on home Proxmox, Traefik on the public IP, Sellix-only, Discord-only. The earlier audit's findings are assumed, not repeated.

## 1. Origin Hiding Architectures

**CDN fronting.** Put the store behind Cloudflare (free tier) or BunnyCDN, then make the origin unreachable to anyone else. Two controls, both required: firewall the origin to accept 80/443 only from the CDN's published ranges, and enable Authenticated Origin Pulls so the origin only accepts TLS with Cloudflare's client certificate — the IP allowlist alone has gaps, since an attacker can point their own Cloudflare zone at your origin IP (https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/, https://www.bigiron.cc/guides/locking-your-origin-to-cloudflare-when-the-proxy-is-not-a-wall). Cloudflare Tunnels removes the open inbound port entirely and suits a home connection behind CGNAT.

**Two-hop shield VPS.** Edge -> DDoS-protected reverse proxy (the "shield") -> private origin. Sellers: Path.net, KoDDoS, CosmicGuard, BlazingFast, typically $5-50/month for reverse-proxy or GRE/IPIP onboarding (https://koddos.net/ddos-proxy-protection.html, https://cosmicguard.com/servers/). The shield owns the public IP; the origin has no public hostname. This decouples origin hiding from Cloudflare's content policies, which matter in genres where Cloudflare itself is a takedown target.

**DNS hygiene — how origins leak.** Standard enumeration finds: historical DNS records from before the proxy, MX/SPF records revealing mail-server IPs on the same box, forgotten direct subdomains, certificate transparency logs listing every hostname you've ever certified (crt.sh), and favicon-hash/cert matching against Shodan/Censys scans (https://www.namesilo.com/blog/en/dns/how-to-find-the-origin-ip-address-behind-cloudflare, https://maddevs.io/writeups/finding-servers-origin-ip/, https://github.com/musana/CF-Hero). Your sslip.io hostname is in CT logs today; that IP must be treated as burned. Rule: a proxy hides an IP only if the IP was never public. Fronting requires a new IP (new VPS or ISP rotation), not just an orange cloud.

**Store vs. license API split.** Split them. The store is public, cacheable, abuse-bait — put it on the CDN, ideally static. The license API must stay reachable from an SDK embedded in distributed software, so it cannot depend on one seizable domain without breaking installed clients. Put the license API on a separate host behind a shield proxy with its own domain, and bake 2-3 endpoint domains plus a fallback resolution mechanism into the SDK so one domain kill doesn't brick validation. Never co-locate it with the store's attack surface.

## 2. Hosting Jurisdiction

"DMCA-ignored" means the provider is outside US jurisdiction and bins complaints — not immune. Recognized names: Shinjiru (Malaysia), AbeloHost (Netherlands), OrangeWebsite (Iceland), VSYS Host (Ukraine), PRQ (Sweden) (https://www.wpwebify.com/blog/5-best-offshore-hosting-providers-dmca-ignored/, https://hostadvice.com/dmca-ignored-hosting/). What survives: DMCA notices, trademark grumbles. What doesn't: local court orders, processor pressure, upstream null-routes, law enforcement. The counter-risk is underweighted: niche providers vanish, exit-scam, or get seized with customer data. Backups are the only mitigation — encrypted, off-site, different jurisdiction, tested restores.

**Home vs VPS.** Home-hosting's appeal: no provider to lean on. Its costs: your residential IP is your identity (abuse complaints go to your ISP, who terminates you), no SLA, and consumer uplinks fold under DDoS. Home-hosting is defensible only behind a shield/tunnel hiding the residential IP. Otherwise a $5-10 offshore VPS plus shield layer is strictly better and cheaper than ISP termination.

## 3. DDoS Reality for One Node

L3/4 volumetric attacks exhaust bandwidth; no local iptables or nginx config survives a multi-Gbps flood on a 1Gbps link — mitigation must happen upstream at an anycast edge. L7 attacks exhaust application resources and are the realistic threat to a proxied API: cache absorbs static requests, but dynamic endpoints pass through to origin (https://hostlist.io/blog/layer-7-vs-layer-3-ddos-why-the-difference-matters, https://coretech.network/blog/layer3-vs-layer7-ddos-attacks/). The proxy absorbs volumetrics, protocol floods, cached content; every uncached request still reaches origin, so origin-side L7 controls (edge rate limits, challenges, bot rules) remain necessary. The economics: a hidden IP costs $0-50/month; volumetric mitigation for an exposed IP costs orders of magnitude more. Hiding beats buying. Ceiling for a 4-core/4GB node: with edge TLS and caching, thousands of rps; uncached dynamic endpoints saturate Postgres long before the network.

## 4. Payment Rail Redundancy

The central fact: **Sellix itself was seized by law enforcement in January 2025 (Operation Talent); sellers lost stores, order history, and balances overnight** (https://sellix.com/, https://sellup.io/blog/sellpass-sellix-shut-down-where-to-sell). If your rail is Sellix today, that is a live incident, not a hypothetical. Options by seizure resistance: (1) **BTCPay Server** self-hosted — non-custodial, no third party to pressure, no KYC; payments go straight to your wallet (https://btcpayserver.org/, https://docs.btcpayserver.org/BTCPayVsOthers/); (2) NOWPayments-class custodial processors — easy, but custody and ToS risk identical to Sellix; (3) direct wallets — zero dependency, zero automation. Recommended shape: BTCPay primary, one hosted processor warm fallback, manual provisioning as cold path — customer pays a published address, opens a ticket with the txid, a human issues the license within N hours. Treasury hygiene: never leave balances on a processor (sweep on a threshold), hot wallet for float only, hardware-wallet cold storage for revenue, and keep only the xpub on the server — never the seed.

## 5. Comms/Identity Resilience

**Discord.** A guild is one report or one compromised admin token from deletion, and your operator account is a second SPOF. Fallbacks: an email list as broadcast-of-last-resort (export customer emails regularly; the one channel no platform can take), a static status page on separate infrastructure, and optionally self-hosted chat (Matrix) as the disaster-recovery community. Discord backup bots (RestoreCord/Parity class) preserve member re-add capability but are ToS-gray — convenience, not strategy (https://dev.to/alikahw/how-to-back-up-your-discord-server-in-2026-the-complete-guide-4fb1, https://www.bigiron.cc/guides/archiving-a-discord-server-before-it-goes-dark).

**Domains.** Registrars and registries kill domains on court orders or abuse pressure; the piracy world's answer is effective: the service survives, the domain is disposable (https://hostija.com/blog/?slug=why-domain-seizures-fail-to-stop-piracy-operations). Keep 2-3 pre-registered mirrors at different registrars/TLDs, registrar-locked, and a channel that outlives any domain (email list, the client's endpoint list) so customers can find the new home.

**Operator opsec.** The storefront persona, code persona, and personal identity must share nothing — no reused handles, emails, avatars, commit times, or writing style. Registrar privacy everywhere; pay for domains/hosting in crypto from a wallet not linked to exchange KYC where lawful. Public GitHub under a personal-adjacent handle is the weakest link in the current setup: commit metadata and issue-tracker slips deanonymize operators more often than any network leak. Move the project to a dedicated org with a dedicated email.

## 6. Prioritized Extras (beyond the earlier audit)

1. **CT log monitoring** for your domains — catch lookalike/phishing certs and your own hostname leaks (https://crt.sh).
2. **Canary tokens** in the repo, config dumps, DB — a tripped token is near-zero-false-positive notice of a leak (https://www.canarytokens.org/).
3. **Dead-man's switch**: an external watcher that pages you, then posts to the status page, if heartbeats stop — covers the bus-factor-1 outage.
4. **Status page on independent infrastructure** as the canonical "are we down" answer.
5. **Registrar lock + WHOIS privacy + registry lock** on all domains, mirrors included.
6. **Egress alerting**: alert on any outbound connection from origin to non-CDN destinations — catches exfil early.
7. **Multi-vantage uptime checks** (3+ regions) to distinguish "we're down" from "one transit path is down" mid-attack.
8. **Artifact leak-response runbook**: pre-written rotate/revoke/notify steps so response is execution, not improvisation.
9. **Shodan/Censys self-scan**: scheduled check that the origin IP isn't visible in internet-scan datasets.
10. **Client-update out-of-band channel**: a signed, versioned endpoint manifest so the SDK learns new domains without a full re-release.

The ordering logic: detection (1-3, 6-7) before response (8), because with a motivated adversary the question is when, not if.
