# Vendored front-end libraries

Pinned copies, embedded into the binary and served from `/static/vendor/`.
The console loads nothing from a CDN: it works on isolated networks, the
Content-Security-Policy can stay `script-src 'self'`, and an upstream
compromise cannot reach a host that manages its own firewall.

app.js loads them on demand (`loadLib`), in the order index.html lists them.

| File | Package | Version | Licence | Used for |
| ---- | ------- | ------- | ------- | -------- |
| d3-array.min.js | d3-array | 3.2.4 | ISC | d3-sankey dependency |
| d3-path.min.js | d3-path | 3.1.0 | ISC | d3-shape dependency |
| d3-shape.min.js | d3-shape | 3.2.0 | ISC | `sankeyLinkHorizontal` |
| d3-selection.min.js | d3-selection | 3.0.0 | ISC | `d3.select` in the Sankey |
| d3-sankey.min.js | d3-sankey | 0.12.3 | BSD-3-Clause | Flows Sankey layout |
| qrcode.js | qrcode-generator | 1.4.4 | MIT (header) | TOTP and WireGuard QR codes |

Fonts in `../fonts/` are IBM Plex Sans 5.0.20 and IBM Plex Mono 5.2.7 latin
subsets from Fontsource, SIL Open Font License 1.1 (`LICENSE-ibm-plex.txt`).

Fetched from `https://cdn.jsdelivr.net/npm/<package>@<version>/…`. To update,
replace the file, update this table, and rebuild: asset URLs carry a content
hash, so browsers pick up the new file on the next page load.
