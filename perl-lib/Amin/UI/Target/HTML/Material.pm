package Amin::UI::Target::HTML::Material;
use v5.38; use warnings; use utf8;

# The HTML target's default look: Material 3 baseline, written against the
# semantic ui: kinds (card, toolbar, button, field, ...) and never against an
# app.  An app emits no CSS to get it.  Every selector is wrapped in :where(),
# so the sheet has zero specificity and any app stylesheet (ui:style) wins
# without a fight.  Colour is the Material role set as custom properties,
# light by default and dark under prefers-color-scheme; a later ui:theme kind
# would only override these properties.  Web only: the Compose target is
# already Material and the SwiftUI target uses system styling.

our $CSS = <<'CSS';
:root{color-scheme:light dark;
--md-primary:#6750a4;--md-on-primary:#fff;--md-primary-container:#eaddff;--md-on-primary-container:#21005d;
--md-secondary-container:#e8def8;--md-on-secondary-container:#1d192b;
--md-background:#fef7ff;--md-on-background:#1d1b20;
--md-surface:#fef7ff;--md-on-surface:#1d1b20;--md-on-surface-variant:#49454f;
--md-surface-container:#f3edf7;--md-surface-container-high:#ece6f0;
--md-outline:#79747e;--md-outline-variant:#cac4d0;--md-error:#b3261e;
--md-radius-s:8px;--md-radius-m:12px;--md-radius-full:999px;
--md-font:Roboto,system-ui,-apple-system,'Segoe UI',sans-serif;
--md-mono:ui-monospace,'JetBrains Mono',Consolas,monospace}
@media (prefers-color-scheme:dark){:root{
--md-primary:#d0bcff;--md-on-primary:#381e72;--md-primary-container:#4f378b;--md-on-primary-container:#eaddff;
--md-secondary-container:#4a4458;--md-on-secondary-container:#e8def8;
--md-background:#141218;--md-on-background:#e6e0e9;
--md-surface:#141218;--md-on-surface:#e6e0e9;--md-on-surface-variant:#cac4d0;
--md-surface-container:#211f26;--md-surface-container-high:#2b2930;
--md-outline:#938f99;--md-outline-variant:#49454f;--md-error:#f2b8b5}}
:where(*){box-sizing:border-box}
:where(body){margin:0;background:var(--md-background);color:var(--md-on-background);font:14px/1.5 var(--md-font)}
:where(p){margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
:where(h2){margin:0;font:500 14px/1.4 var(--md-font);color:var(--md-on-surface-variant);letter-spacing:.01em}
:where(section){display:flex;flex-direction:column;gap:12px}
:where(a){color:var(--md-primary)}
:where(.hstack){display:flex;align-items:center;gap:8px;min-width:0}
:where(.vstack){display:flex;flex-direction:column;gap:6px;min-width:0}
:where(.column){display:flex;flex-direction:column;gap:12px;min-width:0}
:where(.stack){display:flex;min-width:0}
:where(.grid){display:grid;gap:8px}
:where(main){display:block;padding:16px;max-width:880px;margin:0 auto}
:where(main>.column){gap:16px}
:where(main:has(>.hstack)){max-width:1280px}
:where(main>.hstack){align-items:flex-start;gap:16px}
:where(main>.hstack>.column){flex:1 1 0;min-width:0}
@media (max-width:800px){:where(main>.hstack){flex-direction:column;align-items:stretch}}
:where(nav){display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:56px;padding:0 16px;background:var(--md-surface-container);color:var(--md-on-surface);border-bottom:1px solid var(--md-outline-variant)}
:where(nav form){flex-direction:row}
:where(article){display:flex;flex-direction:column;gap:12px;padding:16px;background:var(--md-surface-container);color:var(--md-on-surface);border-radius:var(--md-radius-m)}
:where(article article){background:var(--md-surface-container-high)}
:where(form){margin:0;display:flex;flex-direction:column;gap:12px}
:where(span.label){color:var(--md-on-surface-variant);font-size:12px;letter-spacing:.03em}
:where(span.badge){display:inline-flex;align-items:center;justify-content:center;min-width:20px;height:20px;padding:0 8px;border-radius:var(--md-radius-s);background:var(--md-secondary-container);color:var(--md-on-secondary-container);font:500 12px/1 var(--md-font)}
:where(input,textarea,select){width:100%;padding:10px 12px;background:transparent;color:var(--md-on-surface);border:1px solid var(--md-outline);border-radius:var(--md-radius-s);font:inherit}
:where(textarea){resize:vertical;font-family:var(--md-mono);font-size:13px}
:where(input::placeholder,textarea::placeholder){color:var(--md-on-surface-variant);opacity:.7}
:where(input:focus,textarea:focus,select:focus){outline:2px solid var(--md-primary);outline-offset:-1px;border-color:var(--md-primary)}
:where(input[type=checkbox]){width:18px;height:18px;padding:0;accent-color:var(--md-primary)}
:where(input[type=number]){width:96px}
:where(button){padding:9px 20px;border:0;border-radius:var(--md-radius-full);background:var(--md-primary);color:var(--md-on-primary);font:500 14px var(--md-font);letter-spacing:.01em;cursor:pointer}
:where(button:hover){filter:brightness(1.08)}
:where(button:focus-visible){outline:2px solid var(--md-primary);outline-offset:2px}
:where(nav button,article>.hstack button){background:transparent;color:var(--md-primary);padding:6px 12px}
:where(nav button:hover,article>.hstack button:hover){background:var(--md-secondary-container);filter:none}
:where(audio){width:100%}
:where(figure.player){display:flex;flex-direction:column;gap:10px;margin:0;padding:12px 14px;background:var(--md-surface-container-high);border-radius:var(--md-radius-m)}
:where(figure.player audio){margin:0}
:where(figure.player canvas){display:block;width:100%;height:44px;--axa-eq:var(--md-primary)}
:where(progress){width:100%;accent-color:var(--md-primary)}
:where(div[role=alert]){padding:12px 16px;border-radius:var(--md-radius-s);background:var(--md-surface-container-high);color:var(--md-error);border:1px solid var(--md-error)}
:where(table){border-collapse:collapse;width:100%}
:where(th,td){padding:8px 12px;text-align:left;border-bottom:1px solid var(--md-outline-variant)}
:where(dialog){background:var(--md-surface-container-high);color:var(--md-on-surface);border:0;border-radius:28px;padding:24px}
:where(ul){margin:0;padding-left:20px}
CSS

1;
