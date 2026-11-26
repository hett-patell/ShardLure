# Obsidian and Kiln

ShardLure ships two themes from this release: Obsidian (dark, the default) and Kiln (light). Signal, Meridian and Sprite are gone. A stored legacy preference is read as the nearest new theme and never rewritten on a GET.

## Concept: heat is the signal

Both themes are made by fire. Obsidian is lava cooled into black glass. Kiln is clay fired into porcelain. In both, the interface chrome is the cooled material: quiet, tinted neutrals. The only saturated colour is heat, and it always means one thing: how live, recent or intense a piece of data is. The newest connection is the hottest thing on the screen. Older activity cools back towards the ground.

Status colours (up, stale, failed) are a separate, small vocabulary. Data types are no longer colour-coded. An IP address, a hash and a command are told apart by typeface and position, not by hue.

## Palette

| Role | Obsidian | Kiln |
| --- | --- | --- |
| Ground | `#0e1312` volcanic glass | `#e8ece9` celadon porcelain |
| Sheet (panels) | `#141b1a` | `#f7f9f7` |
| Inset | `#1b2423` | `#dfe5e1` |
| Ink | `#e5ecea` | `#1b2220` |
| Secondary ink | `#93a4a0` | `#4c5753` |
| Live (heat 4) | `#f2843f` ember | `#a2401c` iron red |

Heat runs from 1 (cooled, nearly the ground) to 5 (hottest). On the dark theme hotter is brighter. On the light theme hotter is darker, because pale yellow vanishes on porcelain.

Kiln's neutrals lean towards celadon on purpose. Celadon and iron-red glazes come from the same iron oxide, fired with and without oxygen, so the light theme's two colours belong to one material rather than to the cream-and-terracotta default.

## Type

One family in two widths: Atkinson Hyperlegible Next for interface text and Atkinson Hyperlegible Mono for machine text (IP addresses, hashes, commands, timestamps, counts in tables). The Braille Institute drew it to keep look-alike characters apart: `0`/`O`, `1`/`l`/`I`, `rn`/`m`. That is the confusion that matters when an analyst compares HASSH fingerprints or reads an attacker's `P@ssw0rd`.

Scale: 12, 13, 14, 15, 17, 21, 28 px. Sentence case throughout. No tracked capitals, no monospace labels.

## Layout

Activity page, desktop:

```text
ShardLure   Activity  Intel                            Mumbai, India · updated 15:30
┌──────────────────────────────────────────────────┬───────────────────────────┐
│ 14 actors behind 78 addresses in 8 countries     │ Live feed                 │
│ 3,894 events · 666 shell sessions · 100% hassh   │ ● 4m  89.160.20.219       │
│                                                  │   $ uname -s -v -n -r -m  │
│                 globe (full sphere)              │   b5752e36 · root         │
│                                                  │ ...                       │
│ ● Latest connection, 4m ago                      │                           │
│   Linköping, Sweden  89.160.20.219               │                           │
├──────────────────────────────────────────────────┴───────────────────────────┤
│ Events per hour, last 72 hours  ▁▂▃▅▂▁▂▃▅▇▅▃▁▂▃▅▂▁▂▃▅▇▅▃▁▂▃▅▂▁▂▃   peak 140/h │
├──────────────────────────┬──────────────────────────┬─────────────────────────┤
│ Top source addresses     │ Honeypot                 │ Threat level  36 / 100  │
└──────────────────────────┴──────────────────────────┴─────────────────────────┘
```

The globe is the one loud element and draws one route: from the latest connection's source into the honeypot, in the heat of its age. It does not spin on its own; a new connection replaces the route, pings its two ends and turns the globe to look at it from the side so the arc reads as a curve. Everything else is left-aligned and quiet. There is no separate globe page: two pages, Activity and Intel. Below 760 px the page becomes one column: summary, globe, feed, then the rest.

Intel: one top bar (brand, page links, time window, search), then tabs. Overview opens on the threat actor table. Panels are plain sheets with a hairline edge; tables carry machine text in the mono face and right-aligned tabular numbers.

## Review against the brief

- The first draft used an orange accent for selection, focus and primary buttons. That is the near-black-plus-one-bright-accent default, so interaction states now use ink, and heat is reserved for data.
- The first Kiln draft kept a warm off-white ground. It now leans cool and green, so the light theme is porcelain, not parchment.
- The summary was a big number with small labels. It is now a sentence that puts actors before addresses, which is the product's argument.
- The semicircle threat gauge became a straight heat bar, so the threat level reads on the same scale as everything else.

## Checks

`go test ./internal/web/ ./internal/settings/` covers the contrast floor for every theme token, focus rings, the self-hosted fonts, the settings validation and the legacy-theme mapping. Verify visually in both themes at desktop and phone widths, with reduced motion on.
