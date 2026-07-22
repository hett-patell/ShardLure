# Product

## Register

product

## Platform

web

## Users

Solo security researchers and threat-intel practitioners running personal SSH honeypots on a VPS. Technically fluent — comfortable with CLI, Go binaries, systemd, and SSH config. They operate alone, often on a single cheap droplet, and want the signal density of an enterprise SOC without the enterprise. The dashboard is their war room; the TUI is their forensic bench.

## Product Purpose

ShardLure is an attacker identity engine for SSH honeypot telemetry. It deploys a Cowrie honeypot, clusters attacking bots by behavioral fingerprint (HASSH + username playbook) rather than IP address, classifies intent, captures payloads, enriches IPs against seven providers, and surfaces everything through a real-time web dashboard and forensic TUI. The core value: see *who* is attacking you, not just where from. Same actor roaming three IPs shows as one entity. Different actors sharing an address get different rows.

Success looks like a single operator having full situational awareness of their honeypot — who's hitting it, what they're trying, what they dropped, and where to report it — without stitching together five tools or paying for enterprise SIEM seats.

## Positioning

**Identity over IP.** Every screen reinforces that ShardLure sees the actor behind the address. Behavioral fingerprinting is the lens; everything else (globe, enrichment, MITRE mapping, payload capture, intel sharing) serves that lens.

## Brand Personality

**Cinematic, tactical, underground.** The interface feels like a SOC command center in a thriller — dark, precise, high-density — but never cosplay. The data is real, the operators are real, and the design earns its drama through information density and signal clarity, not decoration. The README voice is irreverent and peer-to-peer ("curl-bash-into-tmp energy", "we are not in our scp era") — the UI carries the tactical weight while the copy stays sharp and human.

## Anti-references

- **Enterprise SIEM dashboards** (Splunk, QRadar, Sentinel): committee-designed, enterprise-blue, 47 tabs of noise. ShardLure is one operator, one screen, full picture.
- **Startup SaaS security tools** (Snyk, Cloudflare dashboard): rounded cards, cheerful illustrations, gradient CTAs. Wrong register entirely — this tool watches malware, not uptime.
- **Gamified hacking platforms** (HackTheBox neon-green, TryHackMe badges): XP bars and achievement unlocks trivialize what ShardLure takes seriously. The data is real threat intel, not a capture-the-flag arcade.
- **Generic dark-mode dev tools**: VS Code / Linear clones with indigo accents and Inter everywhere. ShardLure's darkness is cinematic and warm (Dragon's blood-red-on-near-black), not office-neutral.

## Design Principles

1. **Signal over chrome.** Every pixel earns its place by carrying information. Decoration that doesn't serve comprehension gets cut. A busy panel full of real data is better than a clean panel that hides half of it.
2. **One operator, full picture.** The interface assumes a single person watching one honeypot. No team features, no role-based views, no "upgrade for more." Every screen gives the whole story.
3. **Earn the drama.** The cinematic aesthetic (globe arcs, threat gauges, dark themes) is justified by real operational data, not pasted on for vibes. If the data doesn't support the visual weight, pull back.
4. **Irreverent precision.** Technically rigorous but never stiff. Copy is direct, opinionated, and treats the operator as a peer. No corporate hedging, no hand-holding, no "getting started is easy!"
5. **Identity is the lens.** Actor clustering — not IP, not geography, not time — is the primary organizing principle. When in doubt about how to present data, ask: does this help the operator understand *who* is attacking?

## Accessibility & Inclusion

WCAG AA. 4.5:1 contrast minimum for body text, 3:1 for large text and UI components. Keyboard-navigable panels and modals. Reduced-motion alternatives for globe rotation and arc animations. The dark themes must hit contrast targets — cinematic doesn't mean unreadable.
