# Phosphor dashboard redesign

The dark activity view gives the latest SSH connection a clear place on the globe. The Intel console uses the same visual language and puts actor investigation first.

## Design

| Role | Color |
| --- | --- |
| Background | `#171d22` |
| Work surface | `#212a30` |
| Dividers | `#3a474f` |
| Primary text | `#eef0ed` |
| Secondary text | `#acb7bb` |
| Latest connection | `#ffb18b` |

Barlow carries headings, navigation and labels. IBM Plex Mono identifies values that operators read or compare precisely, such as IPs, timestamps and commands.

```text
ShardLure / Activity                  Activity   Full globe   Intel

Actors and sessions          Globe horizon                Recent activity
                             Latest source

Events per hour
────────────────────────────────────────────────────────────────────────
Source addresses             Honeypot status                 Threat level
```

The globe sits in a full-viewport scene with its own square render surface. The curve has room to read clearly, with a soft fade at the horizon. The copper path tracks the newest geolocated connection. Neutral arcs show prior activity. A small number of working surfaces frame the scene and align with the diagnostics underneath. On phones, the globe and latest source appear above the stacked widgets.

Intel uses a horizontal toolbar, an overview that starts with the actor table, and focused layouts for the existing Blue Team, Red Team, and Settings tabs. The dedicated Full globe page uses the same rendering palette.

## Implementation and checks

1. Update Phosphor layout and material tokens in `internal/web/themes.css`. Give the square Cobe surface matching display and framebuffer geometry in `cobe-globe.js` and `cobe-boot.js`. Verify roundness at desktop and phone widths and while resizing.
2. Update the activity and Intel page structure in `index.html` and `intel.html`. Retain feed, table, chart, navigation, settings, and focus behavior. Verify the layout for each Intel tab and that existing themes remain selectable.
3. Rebuild and start the loopback preview. Inject an event into its demo database and verify the globe turns, the source label changes, and widget data updates in place. Check that reduced-motion mode keeps the scene visible and skips automatic turns. Run the web and CLI tests.
