# octomon brand assets

Colours are sampled from the live TUI, so the site and the tool match exactly.

## Files

- `logo/octomon-logo.svg` — the mark. **Ship this one.** Eight arms drawn as
  probe bars of differing depth; one is amber, because finding the arm that came
  back wrong is what octomon does. Eyes are terminal cursor blocks.
- `logo/octomon-logo-{1024,512,256,128,64,32}.png` — raster fallbacks, transparent.
- `logo/octomon-icon-tile.png` — 512px, mark on an ink rounded square. Favicon,
  app icon, GitHub org avatar.
- `lockup/octomon-lockup-light.png` — mark + wordmark, white text, for dark backgrounds.
- `lockup/octomon-lockup-dark.png` — same, ink text, for light backgrounds.
- `hero/octomon-hero.png` — 2400x1000, fully composed (headline, subhead, install chip).
- `hero/octomon-hero-plain.png` — 2400x1000, same art with the left third left empty.
  Use this and set the headline as real HTML.
- `social/octomon-thumbnail-{a,b}.png` — 1280x720 YouTube thumbnails.
- `tokens.css` — the colour and type variables, plus the Google Fonts import.

## Type

- **Anton** — display only, uppercase, tracking around -0.01em. Never for body.
- **JetBrains Mono** — wordmark, prompts, commands, keyboard shortcuts, data tables.
  The wordmark is lowercase `octomon`, ExtraBold, ~4/176 em letter-spacing.
- **Archivo** — body copy.

## Notes

The hero's dashboard panel is cropped from `screenshot.png` in the repo, so it will
drift as the UI changes. Regenerate from a fresh `octomon --demo` capture when it does.

No OG/Twitter card yet — octomon.dev will want a 1200x630.
