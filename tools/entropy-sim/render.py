# The report page: one self-contained HTML file drawn from WORK/data.json.
# Charts are SVG and canvas built in the page from the embedded numbers.
import json
import os


def de(x, d=1):
    return ("%.*f" % (d, x)).replace(".", ",")


LABELS = {
    "sweep-full": ("Aufgezeichneter Sweep", "PPSSPP, Tastatur statt Daumen: der Stick kennt nur 0, 128 und 255"),
    "sweep.trace": ("Rig-Skript, alt", "dev/testdata/sweep.trace: Richtung aus /dev/urandom, 1 bis 4 Frames je Richtung"),
    "rig-script": ("Rig-Skript, heute", "dev/sweep-trace.py frisch erzeugt: Richtungen aus /dev/urandom"),
    "human #0": ("Simulierte Hand", "an der Aufzeichnung kalibriert: Wendetakt, Haltezeiten, Winkel"),
    "circle": ("Kreis", "Stick im Kreis, 1,5 Umdrehungen pro Sekunde, immer dieselbe Bahn"),
    "spiral": ("Kreis mit Drift", "derselbe Kreis, aber wandernd: findet laufend Neuland"),
    "zigzag": ("Zickzack", "zwei Diagonalen im Wechsel, zwölf Frames je Schenkel"),
    "boundary-22.5": ("Gerade auf 22,5°", "genau auf der Grenze zweier Richtungen, ±1 Zittern, vor den Wänden gespiegelt"),
    "corner": ("Stick in der Ecke", "festgehalten, sonst nichts"),
    "alternate-1": ("Zwei Richtungen, jeder Frame", "rechts, rechts-oben, rechts, …"),
    "alternate-6": ("Zwei Richtungen, alle 6 Frames", "dasselbe, langsam genug für die Haltezeit"),
    "edge-slide": ("An der Wand entlang", "Stick wechselt zwischen Diagonalen, die Wand macht daraus eine Richtung"),
    "switcher": ("Musterwechsler", "Kreis mit Drift, Zickzack, Wechsel: je drei Sekunden, zusammengeschnitten"),
    "switcher-steer": ("Musterwechsler, gelenkt", "dieselben drei Muster, die die echte Quelle steuern und an echten Wänden wenden"),
    "lcg-script": ("LCG-Skript", "Richtungen aus einem 16-Bit-LCG, acht Frames je Richtung"),
}

PAD_LABELS = {
    "turbo-10": ("Turbo 10 Hz", "Kreuz im Dauerfeuer, sechs Frames je Takt"),
    "turbo-12": ("Turbo 12 Hz", "fünf Frames je Takt – gerade nicht mehr zu schnell"),
    "turbo-15": ("Turbo 15 Hz", "vier Frames je Takt"),
    "turbo-30": ("Turbo 30 Hz", "jeder zweite Frame"),
    "two-buttons": ("Zwei Knöpfe im Wechsel", "Kreuz, Kreis, 8 Hz: Abstände 7, 8, 7, 8"),
    "ten-round": ("Alle zehn reihum", "Steuerkreuz, Symbole, Schultern, 10 Hz"),
    "lcg-buttons": ("LCG-Knöpfe", "ein 16-Bit-LCG wählt Knopf und Abstand von 5 bis 12 Frames"),
    "chord-smash": ("Akkord hämmern", "alle vier Symbolknöpfe zugleich, 7,5 Hz"),
    "hold-button": ("Knopf halten", "Kreuz, ununterbrochen"),
    "circle-turbo": ("Kreis plus Turbo", "der Stick kreist, dazu Kreuz im Dauerfeuer mit 15 Hz"),
    "one-button": ("Ein Knopf, menschlicher Takt", "nur Kreuz, aber im Rhythmus eines Menschen"),
}


PAGE = r"""<title>Stick Entropy</title>
<meta name="description" content="Wie viele Bits ein Daumen am PSP-Analogstick in wolfSSLs Seed legt – gemessen an entropy.c von pspkit-https.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans+Condensed:wght@500;600&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;1,400&display=swap">
<style>
:root {
  --ground: #f2f4f7;
  --panel: #ffffff;
  --ink: #161e2c;
  --ink-2: #435066;
  --muted: #6f7a8c;
  --rule: #d6dbe4;
  --rule-soft: #e7eaf0;
  --after: #2b59c3;
  --hard: #2e8b57;
  --before: #b8720e;
  --ok: #1d7446;
  --ok-soft: #dff1e6;
  --warn: #9a3412;
  --warn-soft: #fbe7dc;
  --bit-on: #161e2c;
  --bit-off: #ffffff;
  --code: #e9edf3;
  --sans: "IBM Plex Sans", "Helvetica Neue", Arial, sans-serif;
  --cond: "IBM Plex Sans Condensed", "Arial Narrow", "Helvetica Neue", sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ground: #11151c;
    --panel: #171c25;
    --ink: #e3e7ee;
    --ink-2: #b2bac7;
    --muted: #8691a2;
    --rule: #2b323e;
    --rule-soft: #212733;
    --after: #6189e0;
    --hard: #3e9e6c;
    --before: #b67a26;
    --ok: #6fcf97;
    --ok-soft: #173325;
    --warn: #f4a07a;
    --warn-soft: #3a2218;
    --bit-on: #e3e7ee;
    --bit-off: #171c25;
    --code: #1f2530;
  }
}
:root[data-theme="dark"] {
  --ground: #11151c;
  --panel: #171c25;
  --ink: #e3e7ee;
  --ink-2: #b2bac7;
  --muted: #8691a2;
  --rule: #2b323e;
  --rule-soft: #212733;
  --after: #6189e0;
  --hard: #3e9e6c;
  --before: #b67a26;
  --ok: #6fcf97;
  --ok-soft: #173325;
  --warn: #f4a07a;
  --warn-soft: #3a2218;
  --bit-on: #e3e7ee;
  --bit-off: #171c25;
  --code: #1f2530;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--ground);
  color: var(--ink);
  font: 16px/1.6 var(--sans);
  padding-inline: 20px;
  padding-block: 0 72px;
  -webkit-font-smoothing: antialiased;
}
main { max-width: 1120px; margin: 0 auto; }
.prose { max-width: 68ch; }
h1, h2, h3 { font-family: var(--cond); text-wrap: balance; margin: 0; }
h1 { font-size: clamp(2.6rem, 6vw, 4.2rem); line-height: 1; font-weight: 600; letter-spacing: -0.01em; }
h2 { font-size: 1.75rem; line-height: 1.15; font-weight: 600; }
h3 { font-size: 1.1rem; line-height: 1.25; font-weight: 600; }
p { margin: 0; }
.stack { display: flex; flex-direction: column; gap: 14px; }
.eyebrow { font: 500 0.75rem/1.2 var(--mono); letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); }
code, .mono { font-family: var(--mono); font-size: 0.9em; }
code { background: var(--code); padding: 1px 5px; border-radius: 3px; }
a { color: var(--after); }
header { padding-block: 56px 36px; display: grid; gap: 18px; border-bottom: 1px solid var(--rule); }
.dek { font-size: 1.2rem; line-height: 1.5; color: var(--ink-2); max-width: 62ch; }
.ledger { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0; margin: 10px 0 0; border-top: 1px solid var(--rule); }
.ledger div { padding: 14px 18px 4px 0; display: grid; gap: 4px; align-content: start; }
.ledger div + div { padding-left: 18px; border-left: 1px solid var(--rule); }
.ledger dt { font: 500 0.72rem/1.3 var(--mono); letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
.ledger dd { margin: 0; font: 600 1.9rem/1.1 var(--cond); font-variant-numeric: tabular-nums; }
.ledger dd small { font: 400 0.9rem/1.4 var(--sans); color: var(--ink-2); display: block; margin-top: 4px; }
section { padding-block: 52px 8px; display: grid; gap: 22px; }
section + section { border-top: 1px solid var(--rule); margin-top: 44px; }
.figure { background: var(--panel); border: 1px solid var(--rule); border-radius: 6px; padding: 18px; display: grid; gap: 12px; }
.caption { font-size: 0.88rem; color: var(--ink-2); max-width: 80ch; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 18px; font: 0.8rem/1.3 var(--mono); color: var(--ink-2); }
.legend span { display: inline-flex; align-items: center; gap: 7px; }
.swatch { width: 18px; height: 0; border-top: 2px solid; display: inline-block; }
.swatch.after { border-color: var(--after); }
.swatch.hard { border-color: var(--hard); border-top-style: dashed; }
.swatch.before { border-color: var(--before); }
.swatch.limit { border-top: 2px dashed var(--muted); }
.dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.dot.after { border: 2px solid var(--after); }
.dot.before { background: var(--before); width: 5px; height: 5px; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
th, td { text-align: left; padding: 9px 12px 9px 0; border-bottom: 1px solid var(--rule-soft); vertical-align: top; }
th { font: 500 0.72rem/1.3 var(--mono); letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); border-bottom-color: var(--rule); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; padding-left: 12px; }
td .sub { display: block; color: var(--muted); font-size: 0.8rem; line-height: 1.35; margin-top: 2px; }
.kind { font: 0.72rem/1.2 var(--mono); color: var(--muted); white-space: nowrap; }
.chip { display: inline-block; font: 500 0.72rem/1 var(--mono); padding: 4px 7px; border-radius: 3px; margin-left: 8px; vertical-align: 1px; }
.chip.ok { color: var(--ok); background: var(--ok-soft); }
.chip.warn { color: var(--warn); background: var(--warn-soft); }
.before-v { color: var(--before); }
.hard-v { color: var(--hard); }
.after-v { color: var(--after); font-weight: 600; }
.grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); }
.grid.paths { grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); }
.panel { display: grid; gap: 6px; align-content: start; }
.panel h3 { font-size: 0.98rem; }
.panel .meta { font: 0.75rem/1.35 var(--mono); color: var(--muted); font-variant-numeric: tabular-nums; }
svg { display: block; width: 100%; height: auto; overflow: visible; }
svg text { font-family: var(--mono); font-size: 10px; fill: var(--muted); }
.axis { stroke: var(--rule); stroke-width: 1; fill: none; }
.gridline { stroke: var(--rule-soft); stroke-width: 1; fill: none; }
.limit { stroke: var(--muted); stroke-width: 1; stroke-dasharray: 3 3; fill: none; }
.l-after { stroke: var(--after); stroke-width: 2; fill: none; stroke-linejoin: round; }
.l-hard { stroke: var(--hard); stroke-width: 2; fill: none; stroke-linejoin: round; stroke-dasharray: 5 3; }
.l-before { stroke: var(--before); stroke-width: 2; fill: none; stroke-linejoin: round; }
.field { fill: var(--ground); stroke: var(--rule); }
.trail { stroke: var(--muted); stroke-width: 1; fill: none; opacity: 0.55; stroke-linejoin: round; }
.c-after { fill: none; stroke: var(--after); stroke-width: 1.6; }
.c-before { fill: var(--before); stroke: none; }
.bar-a { fill: var(--after); }
.bar-h { fill: var(--hard); }
.bar-b { fill: var(--before); }
.bar-n { fill: var(--ink-2); }
.expect { stroke: var(--ink); stroke-width: 1.5; fill: none; }
.band { fill: var(--after); opacity: 0.12; }
.band-n { fill: var(--muted); opacity: 0.16; }
.target { fill: var(--ok); opacity: 0.10; }
.hover { stroke: var(--ink); stroke-width: 1; opacity: 0.5; }
.bitmaps { display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); align-items: start; }
.bitmap canvas { width: 100%; max-width: 512px; image-rendering: pixelated; border: 1px solid var(--rule); display: block; background: var(--bit-off); }
.two { display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); align-items: start; }
.heat canvas { width: 100%; max-width: 320px; image-rendering: pixelated; border: 1px solid var(--rule); display: block; }
.scale { display: flex; align-items: center; gap: 8px; font: 0.75rem var(--mono); color: var(--muted); }
.scale canvas { width: 140px; height: 10px; border: 1px solid var(--rule); }
.verdict { border-left: 3px solid var(--warn); padding: 4px 0 4px 16px; font-size: 1.05rem; max-width: 70ch; }
ul.tight { margin: 0; padding-left: 1.2em; display: grid; gap: 8px; }
details { border-top: 1px solid var(--rule); padding-top: 12px; }
summary { cursor: pointer; font: 500 0.85rem var(--mono); color: var(--ink-2); }
summary:focus-visible, a:focus-visible { outline: 2px solid var(--after); outline-offset: 2px; }
pre { background: var(--code); padding: 12px 14px; border-radius: 4px; overflow-x: auto; font: 0.8rem/1.5 var(--mono); margin: 10px 0 0; }
#tip { position: fixed; pointer-events: none; z-index: 10; background: var(--panel); color: var(--ink); border: 1px solid var(--rule); border-radius: 4px; padding: 6px 9px; font: 0.75rem/1.4 var(--mono); box-shadow: 0 4px 16px rgba(10, 16, 30, 0.14); white-space: nowrap; font-variant-numeric: tabular-nums; }
@media (max-width: 640px) {
  .ledger { grid-template-columns: 1fr; }
  .ledger div + div { padding-left: 0; border-left: 0; border-top: 1px solid var(--rule); }
  th, td { padding-right: 8px; }
}
</style>

<main>
<header>
  <span class="eyebrow">pspkit-https · entropy.c · Sweep-Zählung und Pool</span>
  <h1>Stick Entropy</h1>
  <p class="dek">Wie viele Bits ein Daumen am Analogstick der PSP wirklich in den Seed von wolfSSL legt – gemessen am Code der Bibliothek selbst, mit einer echten Aufzeichnung, tausend kalibrierten simulierten Händen, simulierten Knopfdrückern und zwei Dutzend fauler Muster für Stick und Knöpfe. Drei Zählungen nebeneinander: die alte, die erste Härtung und die jetzige.</p>
  <dl class="ledger">
    <div><dt>Schnellster Betrug, alte Zählung</dt><dd>__CHEAP_BEFORE__ s<small>zwei Richtungen im Wechsel, jeder Frame: 128 Bits ohne eine einzige Wahl</small></dd></div>
    <div><dt>Faule Muster jetzt</dt><dd>__LAZY_AFTER__<small>__LAZY_AFTER_SUB__</small></dd></div>
    <div><dt>Ehrlicher Sweep, Median</dt><dd>__H_OLD__ → __H_HARD__ → __H_NEW__ s<small>alt → gehärtet → jetzt, __H_N__ simulierte Hände; Ziel 15–19 s</small></dd></div>
  </dl>
</header>

<section>
  <div class="stack prose">
    <span class="eyebrow">Angriffe und Hände</span>
    <h2>Wann jede Eingabe 128 Bits erreicht</h2>
    <p>Jede Eingabe läuft durch alle drei Zählungen. Die alte gab ein Bit für jedes neue Feld unter einer anderen Stick-Richtung – zwei Richtungen im Wechsel füllten den Balken in zwei Sekunden. Die erste Härtung zählte nur Wendungen, die Prädiktoren nicht vorhersagen konnten, war damit aber auch für ehrliche Hände langsam. Die jetzige zählt zusätzlich den Zeitpunkt jeder Wendung und verlangt dafür, dass eine Wendung gehalten wird. „Alt“ ist nachportiert, „gehärtet“ und „jetzt“ sind die echten <code>entropy.c</code>, unverändert auf dem Host kompiliert.</p>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Eingabe</th><th>Art</th><th class="num">alt</th><th class="num">gehärtet</th><th class="num">jetzt</th></tr></thead>
      <tbody>__TABLE__</tbody>
    </table>
  </div>
  <p class="caption">Muster laufen 600 s, die Hand 120 s. „nie“ heißt: nicht in dieser Zeit, darunter die Bits am Ende. Marken in der letzten Spalte, gemessen am Median ehrlicher Hände jetzt (__H_NEW__ s): „hält“ – nie; „langsam“ – mehr als doppelt so lang; sonst eine Warnung. Skripte sind keine Wahl, aber auch nicht von einer Hand zu unterscheiden; ein zufälliges Skript füllt den Balken zu Recht.</p>
</section>

<section>
  <div class="stack prose">
    <span class="eyebrow">Bits über der Zeit</span>
    <h2>Dieselben Eingaben als Kurven</h2>
    <p>Jedes Feld zeigt die gutgeschriebenen Bits bis 256; die gestrichelte graue Linie ist das Ziel von 128.</p>
  </div>
  <div class="legend"><span><i class="swatch before"></i>alt</span><span><i class="swatch hard"></i>gehärtet</span><span><i class="swatch after"></i>jetzt</span><span><i class="swatch limit"></i>128 Bits</span></div>
  <div class="grid" id="curves"></div>
</section>

<section>
  <div class="stack prose">
    <span class="eyebrow">Die Wege</span>
    <h2>Wo gezahlt wird</h2>
    <p>Das unsichtbare Feld, 250 × 250, von oben: hinten ist oben. Graue Linie: der Weg der Quelle. Kleine Punkte: wo die alte Zählung ein Bit gab. Ringe: wo die jetzige zahlt. Aufzeichnung und Hand bis zum vollen Balken, Muster die ersten 60 Sekunden.</p>
  </div>
  <div class="legend"><span><i class="dot before"></i>Bit, alt</span><span><i class="dot after"></i>Wendung bezahlt, jetzt</span></div>
  <div class="grid paths" id="paths"></div>
</section>

<section>
  <div class="stack prose">
    <span class="eyebrow">Was es kostet</span>
    <h2>Ein ehrlicher Sweep: __H_OLD__ s, __H_HARD__ s, jetzt __H_NEW__ s</h2>
    <p>__HONEST_TEXT__</p>
  </div>
  <div class="figure">
    <div class="legend"><span><i class="swatch before"></i>alt, __N_OLD__ Hände</span><span><i class="swatch hard"></i>gehärtet, __N_HARD__ Hände</span><span><i class="swatch after"></i>jetzt, __N_NEW__ Hände</span></div>
    <div id="durations"></div>
    <p class="caption">Anteil der simulierten Hände, deren Balken im jeweiligen Zwei-Sekunden-Fenster voll wurde; grün hinterlegt das Ziel von 15 bis 19 Sekunden. Dieselben Stickverläufe, einmal durch jede Zählung.</p>
  </div>
</section>

<section>
  <div class="stack prose">
    <span class="eyebrow">Der Maßstab</span>
    <h2>Die simulierte Hand, an der Aufzeichnung geeicht</h2>
    <p>Die einzige echte Aufzeichnung stammt von einer Tastatur in PPSSPP, nicht von einem Daumen; sie misst aber menschlichen Takt. Die simulierte Hand ist ein korrelierter Random Walk im Stickwinkel: Sie entscheidet die nächste Wendung auf einer log-normalen Uhr, meist um 30 bis 60 Grad, rollt mit bis zu 20 Grad pro Frame durch die Richtungen, lässt die Richtung in flachen Kurven wandern, ruht gelegentlich, dreht vor dem Rand ab, und ihr Stick zittert um ein bis zwei Zähler. Ihre Konstanten sind so gewählt, dass sie nach demselben Filter, den die Zählung anwendet, der Aufzeichnung gleicht:</p>
  </div>
  <div class="figure">
    <div class="table-wrap"><table>
      <thead><tr><th>nach Haltezeit und 15°-Regel</th><th class="num">Aufzeichnung</th><th class="num">simulierte Hand</th></tr></thead>
      <tbody>__CALIB__</tbody>
    </table></div>
    <p class="caption">Die Hand streut ihre Haltezeiten so breit wie die Aufzeichnung, nicht breiter: Zeitpunkte zählen jetzt, und eine zu launische Simulation würde sich die Bits selbst schenken.</p>
  </div>
</section>

<section>
  <div class="stack prose">
    <span class="eyebrow">Die Zählung</span>
    <h2>Gezählt wird, was niemand vorhersagen konnte: wohin und wann</h2>
    <ul class="tight">
      <li><strong>Eine Wendung ist eine gehaltene, andere Richtung.</strong> Die Richtung, in die sich die Quelle wirklich bewegt – nach den Wänden –, drei Samples am Stück, und ihre mittlere Bewegung liegt mindestens 15° neben der vorigen. Ein Stick, der auf der Grenze zweier Richtungen zittert, zeigt auf beiden Seiten in dieselbe Richtung und wendet nicht.</li>
      <li><strong>Gezahlt wird nur, was gehalten wird.</strong> Eine Wendung zahlt nur, wenn ihre Richtung eine Sechstelsekunde (zehn Samples) später noch gilt. Wer vorher im selben Drehsinn weiterrollt, macht eine einzige Wendung – ein kreisender Stick bekommt so nichts. Wer vorher in die andere Richtung zurückschnappt, macht einen Wackler, den die Prädiktoren lernen, der aber nichts zahlt.</li>
      <li><strong>Die Richtung wird geraten.</strong> Elf Prädiktoren sehen alle Wendungen des Sweeps: die letzten ein bis vier wiederholt, die häufigste der letzten sechzehn, was nach derselben Folge von ein, zwei, drei Wendungen kam, und die Rückkehr zur Richtung von vor zwei bis vier Wendungen. Es rät der mit der besten jüngeren Bilanz; ein Kontext, der sich schon wiederholt hat, rät zusätzlich.</li>
      <li><strong>Der Zeitpunkt wird geraten.</strong> Die Samples seit der vorigen Wendung, in Klassen je ein Viertel breiter – etwa so fein, wie eine Hand Zeit hält. Acht Prädiktoren: die letzten drei Klassen, die häufigste und der Median der letzten, was nach der letzten Klasse kam, was mit genau dieser Wendung kam, und mit dieser Wendung nach dieser Klasse. Die letzten beiden sehen die Richtung: Eine Hand, deren Takt aus ihren Richtungen folgt, wird dort erraten und bekommt den Zeitpunkt nicht zusätzlich.</li>
      <li><strong>Wand und alter Boden zahlen nicht.</strong> Nach einer Wandberührung zählt die nächste Wendung weder mit Richtung noch mit Zeitpunkt, und eine Wendung zahlt erst auf zwei neuen Feldern.</li>
      <li><strong>Jeder nicht erratene Teil zahlt min(3, −log₂ p ⁄ (1 − p)) Bit.</strong> p ist die obere 99-%-Schranke der Trefferquote des besten Prädiktors für diesen Teil. Über den Sweep gemittelt ist das höchstens −log₂ p pro Wendung, die Min-Entropie aus Sicht der Prädiktoren – für jedes p, weil −ln p ≥ 1 − p. Drei Bit sind die Grenze, weil eine Viertel-Klasse etwa ein Achtel der Haltezeiten einer Hand fasst.</li>
    </ul>
    <p>Was das nicht leistet: Ein Skript ist keine Wahl, und ein zufälliges – <code>dev/sweep-trace.py</code> heute, ein 16-Bit-LCG – kann den Balken füllen; der Musterwechsler braucht __STEER__ s. Die Zählung ist eine untere Schranke gegen faule Hände, kein Beweis gegen einen Gegner, der die Eingabe skriptet.</p>
    <h3>Geprüft und nicht genommen</h3>
    <ul class="tight">
      <li><strong>Stickausschlag als Symbol.</strong> Die einzige Aufzeichnung kennt nur Vollausschlag, und wie weit ein Daumen den Nub drückt, weiß niemand; gezählt würde nur, was sich die Simulation ausgedacht hat.</li>
      <li><strong>16 Richtungen.</strong> Aus demselben Grund, und ein feineres Raster öffnet dem Grenzzittern die Tür wieder.</li>
      <li><strong>Zeitpunkte auch bei erratenen Richtungen, ohne Haltepflicht.</strong> Ehrliche Hände 14 s, aber Kreis mit Drift und gelenkter Musterwechsler lagen dann mit 12 bis 23 s gleichauf oder vorn.</li>
      <li><strong>Treffer im Zeitpunkt schon bei ±1 Klasse.</strong> Sehr vorsichtig, aber ehrliche Hände über 20 s.</li>
      <li><strong>Mehr als drei Bit je Teil.</strong> Brachte nichts: Die Grenze greift kaum, weil die Schranke selbst darunter liegt.</li>
    </ul>
  </div>
</section>

<section>
  <div class="stack prose">
    <span class="eyebrow">Knöpfe</span>
    <h2>Wer drückt, zahlt ein – aber nur für Wahl</h2>
    <p>Während des Sweeps darf die Hand auch Knöpfe drücken: Steuerkreuz, Dreieck, Kreis, Kreuz, Quadrat, L und R. START, SELECT und HOME gehören dem Bildschirm; sie gehen wie jede Knopfänderung mit ihrem Zeitpunkt in den Pool, zählen aber nichts. Gezählt wird wie bei den Wendungen, was niemand vorhersagen konnte:</p>
    <ul class="tight">
      <li><strong>Ein Druck ist ein Knopf, der hinuntergeht.</strong> Halten zahlt nichts. Gehen mehrere Knöpfe im selben Frame hinunter, ist das ein Akkord: Den hat die Breite des Daumens gewählt oder ein Turbo-Pad; er wird als Zeitpunkt gemerkt und zahlt nichts.</li>
      <li><strong>Zu schnell zahlt nicht.</strong> Ein Druck weniger als fünf Frames nach dem vorigen ist gehetzt – schneller, als ein Daumen einen Knopf wählt; so drückt ein Turbo-Pad. Die Prädiktoren lernen ihn trotzdem.</li>
      <li><strong>Der Knopf wird geraten.</strong> Acht Prädiktoren: die letzten ein bis drei Knöpfe, der häufigste der letzten sechzehn, was nach demselben einen und denselben zwei Knöpfen kam, der nächste Schritt reihum auf Steuerkreuz oder Symbolen in der Richtung der letzten zwei, und der Liebling der Gruppe, auf der der Daumen gerade liegt.</li>
      <li><strong>Der Zeitpunkt wird geraten</strong> – mit den Klassen der Wendungen, den Prädiktoren der Wendungen und dazu einem Rhythmus: dem Mittel der letzten vier Abstände. Eine Klasse daneben gilt als erraten, denn ein Daumen verschiebt seinen Takt um einen Frame, ohne etwas zu wählen.</li>
      <li><strong>Was nicht erraten wurde, zahlt:</strong> der Knopf bis zu 2 Bit, der Zeitpunkt bis zu 2 Bit – dieser aber nur, wenn auch der Knopf nicht erraten wurde. Wer immer denselben Knopf trommelt, hält einen Rhythmus, er wählt nicht. Zwei Bit je Teil, weil ein Daumen beim Hämmern etwa vier Knöpfe wirklich benutzt und sein Takt in drei, vier Klassen fällt.</li>
      <li><strong>Eine Decke.</strong> Knöpfe zahlen höchstens 11,25 Bit pro Sekunde und sparen in Pausen höchstens 3 Bit an. Das ist keine Schätzung, sondern ein Deckel: Mehr echte Entscheidungen pro Sekunde trifft keine Hand, und ein Skript kann beliebig viele vortäuschen. Aus den Knöpfen allein füllt nichts den Balken in unter elf Sekunden.</li>
    </ul>
    <p>Stick und Knöpfe werden getrennt gezählt und addiert: Es sind zwei Hände, und die Prädiktoren der einen sehen die andere nicht.</p>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Knopf-Muster</th><th class="num">128 Bits nach</th><th class="num">bezahlte Drücke</th></tr></thead>
      <tbody>__PAD_TABLE__</tbody>
    </table>
  </div>
  <p class="caption">Jedes Muster 600 s, der Stick in Ruhe (außer beim Kreis). Die alte Zählung und die erste Härtung kannten keine Knöpfe. Marken gemessen am Median ehrlicher Knopfdrücker (__PAD_MED__ s): „hält“ – nie; „langsam“ – mehr als doppelt so lang; das LCG ist ein Skript und landet an der Decke.</p>
  <div class="figure">
    <h3>Wie lang ein ehrlicher Sweep dauert: Stick, Knöpfe, beides</h3>
    <div id="pad-durations"></div>
    <p class="caption">__PAD_TEXT__</p>
  </div>
  <div class="stack prose">
    <h3>Der Knopfdrücker ist geschätzt, nicht gemessen</h3>
    <p>Es gibt keine Aufzeichnung von jemandem, der auf der PSP Knöpfe hämmert. Das Modell ist deshalb vorsichtig gewählt: Salven von etwa zwölf Drücken mit 7 Frames Median-Abstand (8,6 pro Sekunde), Abstände nur um 0,20 im Logarithmus gestreut, Pausen um 0,6 s, jeder Druck zwei bis drei Frames gehalten, und ein Daumen, der meist auf dem Knopf bleibt oder zum Nachbarn rollt; gelegentlich Steuerkreuz oder Schulter. Die gemischte Hand wechselt ab: drei bis sechs Sekunden Stick mit der kalibrierten Hand, zwei bis vier Sekunden Knöpfe. Streuung 0,12 oder 0,35 statt 0,20 und 6 statt 8,6 Drücke pro Sekunde ändern den Median um weniger als zwei Sekunden, weil die Decke und die Knopfwahl die Rechnung bestimmen, nicht der Takt.</p>
    <h3>Geprüft und nicht genommen</h3>
    <ul class="tight">
      <li><strong>Zeitpunkt auch bei erratenem Knopf.</strong> Ein einzelner Knopf im menschlichen Takt füllte den Balken dann in 22 s, so schnell wie ehrliches Hämmern.</li>
      <li><strong>Zeitpunkt nur bei exakt getroffener Klasse.</strong> Bezahlt einen Frame Zittern; kaum schneller für Menschen, großzügiger für Rhythmen.</li>
      <li><strong>Decke von 7,5 Bit pro Sekunde.</strong> Ehrliche Drücker bei 22 s, langsamer als der Stick. <strong>15 Bit pro Sekunde:</strong> das LCG-Skript bei 10 s.</li>
      <li><strong>Akkord als eigenes Symbol.</strong> Ein Turbo-Pad auf mehreren Knöpfen erzeugt Akkorde am laufenden Band; welche Knöpfe mitkamen, entscheidet die Hand kaum.</li>
      <li><strong>Haltedauer eines Drucks.</strong> Geht in den Pool, zählt aber nicht: Wie lang ein Daumen einen Knopf hält, weiß niemand, und das Modell würde es erfinden.</li>
    </ul>
  </div>
</section>

<section>
  <div class="stack prose">
    <span class="eyebrow">Was wolfSSL bekommt</span>
    <h2>__GOOD_N__ Sweeps, je die ersten 64 Byte des Seeds</h2>
    <p>Jede simulierte Hand mit eigenem Zufallsseed fegt, bis der Balken voll ist; dann zieht der Test, was <code>pspkit_https_seed</code> an wolfSSL gäbe, und speichert die Seed-Datei. Die simulierte Uhr hat pro Frame ±150 µs Jitter. Eine Zeile pro Sweep, ein Pixel pro Bit.</p>
  </div>
  <div class="bitmaps">
    <div class="bitmap panel"><h3>Seed-Bytes, 512 × 512 Bit</h3><canvas id="bm-good" width="512" height="512"></canvas><span class="meta">512 Sweeps × 64 Byte</span></div>
    <div class="bitmap panel"><h3>Seed-Dateien, 512 × 256 Bit</h3><canvas id="bm-files" width="256" height="512"></canvas><span class="meta">512 Sweeps × 32 Byte</span></div>
  </div>
  <div class="two">
    <div class="figure"><h3>Byte-Werte</h3><div id="hist-good"></div><p class="caption">__GOOD_BYTES__ Byte auf 256 Werte; Linie: Erwartung __EXPECT__ je Wert, Band: ±2σ. χ² = __CHI2__ bei 255 Freiheitsgraden, p = __PCHI__.</p></div>
    <div class="figure"><h3>Anteil Einsen je Bitposition</h3><div id="bias-good"></div><p class="caption">512 Bitpositionen über __GOOD_N__ Sweeps; Band: 0,5 ± 3σ (σ = __SIGMA__). Außerhalb: __OUT3__, erwartet etwa 1,4.</p></div>
  </div>
  <div class="two">
    <div class="figure heat"><h3>Korrelation der ersten 64 Bitpositionen</h3><canvas id="heat-good" width="64" height="64"></canvas><div class="scale"><span>−0,15</span><canvas id="heat-scale" width="140" height="1"></canvas><span>+0,15</span></div><p class="caption">Pearson-r je Paar über alle Sweeps; die Diagonale ist ausgeblendet. Größtes |r| unter 2016 Paaren: __CORR__, bei σ = __CORRSIG__ sind etwa 3,5σ zu erwarten.</p></div>
    <div class="figure"><h3>Kennzahlen</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Test</th><th class="num">Seeds</th><th class="num">Dateien</th><th class="num">ideal</th></tr></thead>
        <tbody>__STATS_GOOD__</tbody>
      </table></div>
      <p class="caption">ent-Kennzahlen (Entropie je Byte, Mittelwert, serielle Korrelation, Monte-Carlo-π auf 24-Bit-Koordinaten), Runs-Test über den Bitstrom, Hamming-Abstand aufeinanderfolgender Sweeps.</p>
    </div>
  </div>
</section>

<section>
  <div class="stack prose">
    <span class="eyebrow">Die Gegenprobe</span>
    <h2>Ein kaputter Pool sieht genauso zufällig aus</h2>
    <p class="verdict">Alle Bilder oben würden auch ein Pool bestehen, der fast nichts enthält. SHA-256 macht aus jeder Eingabe Bytes, die jeden Test bestehen. Die Frage ist nie, ob der Seed zufällig aussieht, sondern wie viel unvorhersagbare Eingabe gezählt wurde – und genau das misst die Zählung oben.</p>
    <p>Derselbe Code, derselbe Pfad, zwei absichtlich kaputte Varianten: die Uhr ohne Jitter (jeder Lesezugriff +1 µs, jeder Frame genau 16 667 µs), keine Adressraum-Randomisierung, und als Eingabe entweder (A) immer dieselbe Hand, 512 aufeinanderfolgende Züge aus einem Pool, oder (B) die Hände mit den Seeds 0 bis 511. A enthält null Bit, B genau neun: Wer den Walker kennt, probiert 512 Kandidaten. B zweimal in getrennten Prozessen gerechnet: __B2_REPRO__.</p>
  </div>
  <div class="bitmaps">
    <div class="bitmap panel"><h3>B · Seeds 0–511, Uhr ohne Jitter</h3><canvas id="bm-broken" width="512" height="512"></canvas><span class="meta">9 Bit Eingabe, 512 × 512 Bit Ausgabe</span></div>
    <div class="figure"><h3>Byte-Werte, B</h3><div id="hist-broken"></div><p class="caption">χ² = __B_CHI2__, p = __B_PCHI__. Besteht.</p></div>
  </div>
  <div class="figure"><h3>Kennzahlen im Vergleich</h3>
    <div class="table-wrap"><table>
      <thead><tr><th>Test</th><th class="num">echte Sweeps</th><th class="num">A · 0 Bit</th><th class="num">B · 9 Bit</th><th class="num">ideal</th></tr></thead>
      <tbody>__STATS_BROKEN__</tbody>
    </table></div>
  </div>
</section>

<section>
  <div class="stack prose">
    <span class="eyebrow">Pool und Datei</span>
    <h2>Was sich außer der Zählung geändert hat</h2>
    <ul class="tight">
      <li><strong>SHA-256 statt SHA-1.</strong> Der alte Pool hashte <code>pool || data</code> und schnitt Daten nach 64 Byte ab – heutige Aufrufer blieben darunter, <code>entropy_stir</code> nahm aber beliebige Längen an. Jetzt: SHA-256 über Pool, Art, Länge und Daten, ganz. Der Zustand hält 256 statt 160 Bit, und wolfCrypts DRBG ist ohnehin SHA-256.</li>
      <li><strong>Ziehen mit Ratsche.</strong> Jeder Block ist <code>H(pool, SEED, zähler)</code>, danach rückt der Pool unter anderem Tag weiter. Die Ausgabe fließt nicht mehr in den Pool zurück, und ein später ausgelesener Pool verrät keine früheren Züge.</li>
      <li><strong>Kein Seed ohne vollen Pool.</strong> <code>pspkit_https_seed</code> schlägt fehl, solange der Pool nie voll war; während eines zweiten Sweeps nach <code>entropy_stash</code> bleibt er erlaubt. <code>entropy_save</code> schreibt nichts aus einem nie vollen Pool und meldet Schreibfehler.</li>
      <li><strong>Seed-Datei 32 Byte, beim Laden sofort ersetzt.</strong> 20-Byte-Dateien werden abgewiesen und kosten einen Sweep. Stirbt ein Lauf vor dem Speichern, startet der nächste nicht vom selben Seed. Die Uhr (RTC) geht beim Start ungezählt mit ein.</li>
      <li><strong>Sperren.</strong> Eine Pool-Sperre für Sekundenbruchteile, eine Datei-Sperre, immer vorher genommen; ein Handshake wartet nie auf den Memory Stick. Zählerstände werden unter der Sperre gelesen.</li>
    </ul>
  </div>
  <details>
    <summary>Selbsttest des Host-Builds</summary>
    <pre>__SELFTEST__</pre>
  </details>
  <details>
    <summary>Nachrechnen</summary>
    <pre>cd tools/entropy-sim
make &amp;&amp; ./sim selftest
python3 report.py compute WORK ../../../pspdx/dev/testdata
python3 report.py render WORK entropy-report.html</pre>
  </details>
</section>
</main>
<div id="tip" hidden></div>

<script>
const D = __DATA__;
const NS = "http://www.w3.org/2000/svg";
const tip = document.getElementById("tip");
function el(tag, attrs, parent) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(e);
  return e;
}
function de(x, d) { return x.toFixed(d).replace(".", ","); }
function showTip(ev, html) {
  tip.innerHTML = html;
  tip.hidden = false;
  const r = tip.getBoundingClientRect();
  let x = ev.clientX + 14, y = ev.clientY + 14;
  if (x + r.width > innerWidth - 8) x = ev.clientX - r.width - 14;
  if (y + r.height > innerHeight - 8) y = ev.clientY - r.height - 14;
  tip.style.left = x + "px";
  tip.style.top = y + "px";
}
function hideTip() { tip.hidden = true; }
function niceTicks(max, n) {
  const raw = max / n, mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 5, 10].map(m => m * mag).find(s => s >= raw);
  const out = [];
  for (let v = 0; v <= max + 1e-9; v += step) out.push(Math.round(v * 1000) / 1000);
  return out;
}
function stepAt(curve, t) {
  let b = 0;
  for (const [ct, cb] of curve) { if (ct > t) break; b = cb; }
  return b;
}
const SERIES = [["old_curve", "l-before", "alt", "--before"], ["hard_curve", "l-hard", "gehärtet", "--hard"], ["new_curve", "l-after", "jetzt", "--after"]];

(function curves() {
  const host = document.getElementById("curves");
  for (const row of D.table) {
    const div = document.createElement("div");
    div.className = "panel figure";
    const title = document.createElement("h3");
    title.textContent = row.label;
    const meta = document.createElement("span");
    meta.className = "meta";
    const f = v => v === null ? "nie" : de(v, 1) + " s";
    meta.textContent = f(row.old_full) + " · " + f(row.hard_full) + " · " + f(row.new_full);
    div.append(title, meta);
    const W = 260, H = 150, L = 30, R = 8, T = 8, B = 22;
    const tmax = row.seconds;
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": row.label });
    const x = t => L + (W - L - R) * t / tmax, y = b => T + (H - T - B) * (1 - Math.min(b, 256) / 256);
    const clipId = "clip-" + Math.random().toString(36).slice(2);
    const defs = el("defs", {}, svg);
    el("rect", { x: L, y: T - 1, width: W - L - R, height: H - T - B + 1 }, el("clipPath", { id: clipId }, defs));
    for (const b of [0, 128, 256]) {
      el("line", { x1: L, x2: W - R, y1: y(b), y2: y(b), class: b === 128 ? "limit" : "gridline" }, svg);
      const tx = el("text", { x: L - 5, y: y(b) + 3, "text-anchor": "end" }, svg);
      tx.textContent = b;
    }
    for (const t of niceTicks(tmax, 3)) {
      const tx = el("text", { x: x(t), y: H - 6, "text-anchor": t === 0 ? "start" : "middle" }, svg);
      tx.textContent = t + (t === 0 ? "" : " s");
    }
    el("line", { x1: L, x2: W - R, y1: y(0), y2: y(0), class: "axis" }, svg);
    const g = el("g", { "clip-path": `url(#${clipId})` }, svg);
    const pathOf = (curve) => {
      let d = `M${x(0)},${y(0)}`;
      for (const [t, b] of curve) d += `H${x(t)}V${y(b)}`;
      return d + `H${x(tmax)}`;
    };
    for (const [key, cls] of SERIES) el("path", { d: pathOf(row[key]), class: cls }, g);
    const hover = el("line", { y1: T, y2: H - B, class: "hover", visibility: "hidden" }, svg);
    const hit = el("rect", { x: L, y: T, width: W - L - R, height: H - T - B, fill: "transparent" }, svg);
    hit.addEventListener("pointermove", ev => {
      const r = svg.getBoundingClientRect();
      const px = (ev.clientX - r.left) * W / r.width;
      const t = Math.max(0, Math.min(tmax, (px - L) / (W - L - R) * tmax));
      hover.setAttribute("x1", x(t)); hover.setAttribute("x2", x(t)); hover.setAttribute("visibility", "visible");
      showTip(ev, `${row.label} · ${de(t, 1)} s` + SERIES.map(([k, , name, tok]) => `<br><span style="color:var(${tok})">${name} ${stepAt(row[k], t)} Bit</span>`).join(""));
    });
    hit.addEventListener("pointerleave", () => { hover.setAttribute("visibility", "hidden"); hideTip(); });
    div.appendChild(svg);
    host.appendChild(div);
  }
})();

(function paths() {
  const host = document.getElementById("paths");
  for (const row of D.table) {
    if (!row.path) continue;
    const div = document.createElement("div");
    div.className = "panel figure";
    const title = document.createElement("h3");
    title.textContent = row.label;
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = `${de(row.path_seconds, 1)} s · alt ${row.old_credited.length} Bit · jetzt ${row.credited.length} Wendungen bezahlt`;
    div.append(title, meta);
    const S = 250, P = 4;
    const svg = el("svg", { viewBox: `${-P} ${-P} ${S + 2 * P} ${S + 2 * P}`, role: "img", "aria-label": "Weg: " + row.label });
    el("rect", { x: 0, y: 0, width: S, height: S, class: "field" }, svg);
    const px = p => [p[0] * S, (1 - p[1]) * S];
    el("polyline", { points: row.path.map(p => px(p).map(v => v.toFixed(1)).join(",")).join(" "), class: "trail" }, svg);
    for (const p of row.old_credited) { const [a, b] = px(p); el("circle", { cx: a, cy: b, r: 1.3, class: "c-before" }, svg); }
    for (const p of row.credited) { const [a, b] = px(p); el("circle", { cx: a, cy: b, r: 4, class: "c-after" }, svg); }
    div.appendChild(svg);
    host.appendChild(div);
  }
})();

function durations(id, sets) {
  const host = document.getElementById(id);
  const tmax = Math.min(120, Math.ceil(Math.max(...sets.map(s => s[1].p90)) * 1.35 / 10) * 10);
  const W = 720, rowH = 86, gap = 8, L = 40, R = 10, T = 10, B = 26, H = T + sets.length * (rowH + gap) + B;
  const bin = 2, bins = tmax / bin;
  const hist = arr => { const h = new Array(bins).fill(0); for (const t of arr) { const i = Math.floor(t / bin); if (i >= 0 && i < bins) h[i]++; } return h.map(c => c / arr.length); };
  const ymax = Math.max(...sets.map(s => Math.max(...hist(s[1].times))));
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Dauer bis 128 Bit" });
  const x = t => L + (W - L - R) * t / tmax;
  el("rect", { x: x(15), y: T, width: x(19) - x(15), height: sets.length * (rowH + gap) - gap, class: "target" }, svg);
  sets.forEach(([name, s, cls], k) => {
    const top = T + k * (rowH + gap), base = top + rowH, h = hist(s.times);
    el("line", { x1: L, x2: W - R, y1: base, y2: base, class: "axis" }, svg);
    const lab = el("text", { x: L, y: top + 10 }, svg);
    lab.textContent = `${name} · Median ${de(s.median, 1)} s`;
    h.forEach((v, i) => {
      if (!v) return;
      const bh = (rowH - 16) * v / ymax;
      const r = el("rect", { x: x(i * bin) + 1, y: base - bh, width: (W - L - R) / bins - 2, height: bh, rx: 2, class: cls }, svg);
      r.addEventListener("pointermove", ev => showTip(ev, `${name} · ${i * bin}–${(i + 1) * bin} s<br>${de(v * 100, 1)} % von ${s.times.length} Händen`));
      r.addEventListener("pointerleave", hideTip);
    });
  });
  for (let t = 0; t <= tmax; t += 10) {
    const tx = el("text", { x: x(t), y: H - 8, "text-anchor": "middle" }, svg);
    tx.textContent = t + " s";
  }
  host.appendChild(svg);
}
durations("durations", [["alt", D.humans.old, "bar-b"], ["gehärtet", D.humans.hard, "bar-h"], ["jetzt", D.humans.new, "bar-a"]]);
durations("pad-durations", [["Stick allein", D.humans.new, "bar-a"], ["Knöpfe allein", D.pads.masher, "bar-a"], ["Stick und Knöpfe im Wechsel", D.pads.mixed, "bar-a"]]);

function byteHist(id, s) {
  const host = document.getElementById(id);
  const W = 520, H = 190, L = 34, R = 6, T = 8, B = 22;
  const e = s.bytes / 256, sd = Math.sqrt(e * (1 - 1 / 256));
  const ymin = Math.floor((Math.min(...s.hist, e - 3 * sd)) / 10) * 10, ymax = Math.ceil((Math.max(...s.hist, e + 3 * sd)) / 10) * 10;
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Histogramm der Bytewerte" });
  const x = v => L + (W - L - R) * v / 256, y = c => T + (H - T - B) * (1 - (c - ymin) / (ymax - ymin));
  el("rect", { x: L, y: y(e + 2 * sd), width: W - L - R, height: y(e - 2 * sd) - y(e + 2 * sd), class: "band-n" }, svg);
  for (const c of [ymin, Math.round(e), ymax]) { const t = el("text", { x: L - 4, y: y(c) + 3, "text-anchor": "end" }, svg); t.textContent = c; }
  for (const v of [0, 64, 128, 192, 255]) { const t = el("text", { x: x(v + 0.5), y: H - 6, "text-anchor": "middle" }, svg); t.textContent = v; }
  s.hist.forEach((c, v) => {
    const r = el("rect", { x: x(v), y: Math.min(y(c), y(ymin)), width: Math.max(1, (W - L - R) / 256 - 0.4), height: Math.abs(y(ymin) - y(c)), class: "bar-n" }, svg);
    r.addEventListener("pointermove", ev => showTip(ev, `Byte ${v} (0x${v.toString(16).padStart(2, "0")})<br>${c}× · erwartet ${de(e, 0)}`));
    r.addEventListener("pointerleave", hideTip);
  });
  el("line", { x1: L, x2: W - R, y1: y(e), y2: y(e), class: "expect" }, svg);
  host.appendChild(svg);
}
function bias(id, s) {
  const host = document.getElementById(id);
  const W = 520, H = 190, L = 40, R = 6, T = 8, B = 22, n = s.bias.length;
  const span = Math.max(5 * s.sigma, ...s.bias.map(b => Math.abs(b - 0.5))) * 1.05;
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Anteil Einsen je Bitposition" });
  const x = i => L + (W - L - R) * (i + 0.5) / n, y = b => T + (H - T - B) * (1 - (b - (0.5 - span)) / (2 * span));
  el("rect", { x: L, y: y(0.5 + 3 * s.sigma), width: W - L - R, height: y(0.5 - 3 * s.sigma) - y(0.5 + 3 * s.sigma), class: "band" }, svg);
  el("line", { x1: L, x2: W - R, y1: y(0.5), y2: y(0.5), class: "expect" }, svg);
  for (const b of [0.5 - 3 * s.sigma, 0.5, 0.5 + 3 * s.sigma]) { const t = el("text", { x: L - 4, y: y(b) + 3, "text-anchor": "end" }, svg); t.textContent = de(b, 3); }
  for (const i of [0, 128, 256, 384, 511]) { if (i >= n) continue; const t = el("text", { x: x(i), y: H - 6, "text-anchor": "middle" }, svg); t.textContent = i; }
  s.bias.forEach((b, i) => {
    const out = Math.abs(b - 0.5) > 3 * s.sigma;
    const c = el("circle", { cx: x(i), cy: y(b), r: out ? 3 : 1.6, class: out ? "c-after" : "bar-n" }, svg);
    c.addEventListener("pointermove", ev => showTip(ev, `Bit ${i}<br>${de(b * 100, 2)} % Einsen · ${de((b - 0.5) / s.sigma, 2)} σ`));
    c.addEventListener("pointerleave", hideTip);
  });
  host.appendChild(svg);
}
byteHist("hist-good", D.good);
byteHist("hist-broken", D.broken_seeds);
bias("bias-good", D.good);

function tokens() {
  const cs = getComputedStyle(document.documentElement);
  const get = n => cs.getPropertyValue(n).trim();
  return { on: get("--bit-on"), off: get("--bit-off"), after: get("--after"), before: get("--before"), panel: get("--panel") };
}
function rgb(hex) { const h = hex.replace("#", ""); return [0, 2, 4].map(i => parseInt(h.slice(i, i + 2), 16)); }
function bitmap(id, b64, bytesPerRow) {
  const c = document.getElementById(id), ctx = c.getContext("2d");
  const raw = atob(b64), rows = Math.min(512, raw.length / bytesPerRow);
  const img = ctx.createImageData(bytesPerRow * 8, rows), t = tokens(), on = rgb(t.on), off = rgb(t.off);
  for (let r = 0; r < rows; r++)
    for (let b = 0; b < bytesPerRow; b++) {
      const v = raw.charCodeAt(r * bytesPerRow + b);
      for (let k = 0; k < 8; k++) {
        const bit = (v >> (7 - k)) & 1, p = (r * bytesPerRow * 8 + b * 8 + k) * 4, col = bit ? on : off;
        img.data[p] = col[0]; img.data[p + 1] = col[1]; img.data[p + 2] = col[2]; img.data[p + 3] = 255;
      }
    }
  ctx.putImageData(img, 0, 0);
}
function diverge(v, t) {
  const m = rgb(t.panel), pos = rgb(t.after), neg = rgb(t.before), a = Math.min(1, Math.abs(v) / 0.15), end = v >= 0 ? pos : neg;
  return m.map((c, i) => Math.round(c + (end[i] - c) * a));
}
function heat(id, corr) {
  const c = document.getElementById(id), ctx = c.getContext("2d"), n = corr.length, img = ctx.createImageData(n, n), t = tokens();
  for (let a = 0; a < n; a++) for (let b = 0; b < n; b++) {
    const col = a === b ? rgb(t.panel) : diverge(corr[a][b], t), p = (a * n + b) * 4;
    img.data[p] = col[0]; img.data[p + 1] = col[1]; img.data[p + 2] = col[2]; img.data[p + 3] = 255;
  }
  ctx.putImageData(img, 0, 0);
  const s = document.getElementById("heat-scale"), sx = s.getContext("2d"), si = sx.createImageData(140, 1);
  for (let i = 0; i < 140; i++) { const col = diverge((i / 139 - 0.5) * 0.3, t), p = i * 4; si.data[p] = col[0]; si.data[p + 1] = col[1]; si.data[p + 2] = col[2]; si.data[p + 3] = 255; }
  sx.putImageData(si, 0, 0);
  if (!c.dataset.bound) {
    c.dataset.bound = "1";
    c.addEventListener("pointermove", ev => {
      const r = c.getBoundingClientRect(), b = Math.floor((ev.clientX - r.left) / r.width * n), a = Math.floor((ev.clientY - r.top) / r.height * n);
      if (a < 0 || b < 0 || a >= n || b >= n) return hideTip();
      showTip(ev, a === b ? `Bit ${a}` : `Bit ${a} × Bit ${b}<br>r = ${de(corr[a][b], 3)}`);
    });
    c.addEventListener("pointerleave", hideTip);
  }
}
function canvases() {
  bitmap("bm-good", D.bitmaps.good, 64);
  bitmap("bm-files", D.bitmaps.files, 32);
  bitmap("bm-broken", D.bitmaps.broken_seeds, 64);
  heat("heat-good", D.good.corr);
}
canvases();
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", canvases);
new MutationObserver(canvases).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
</script>
"""


def render(work, out):
    with open(os.path.join(work, "data.json")) as f:
        data = json.load(f)
    table = data["table"]
    by = {r["name"]: r for r in table}
    humans = data["humans"]
    hn = humans["new"]

    def cell(full, bits, seconds):
        if full is not None:
            return de(full) + " s"
        return "nie <span class=\"sub\">%d Bit in %s s</span>" % (bits, de(seconds, 0))

    rows = []
    for r in table:
        label, sub = LABELS.get(r["name"], (r["name"], ""))
        r["label"] = label
        chip = ""
        if r["kind"] == "cheap pattern":
            if r["new_full"] is None:
                chip = '<span class="chip ok">hält</span>'
            elif r["new_full"] > 2 * hn["median"]:
                chip = '<span class="chip ok">langsam</span>'
            else:
                chip = '<span class="chip warn">nah an einer Hand</span>'
        kind = {"recorded": "aufgezeichnet", "script": "Skript", "simulated hand": "Simulation",
                "cheap pattern": "faules Muster"}[r["kind"]]
        rows.append(
            "<tr><td><strong>%s</strong><span class=\"sub\">%s</span></td><td class=\"kind\">%s</td>"
            "<td class=\"num before-v\">%s</td><td class=\"num hard-v\">%s</td>"
            "<td class=\"num\"><span class=\"after-v\">%s</span>%s</td></tr>" % (
                label, sub, kind, cell(r["old_full"], r["old_bits"], r["seconds"]),
                cell(r["hard_full"], r["hard_bits"], r["seconds"]),
                cell(r["new_full"], r["new_bits"], r["seconds"]), chip))

    def stat_rows(cols):
        spec = [
            ("χ² der Bytewerte (p)", lambda s: "%s (%s)" % (de(s["chi2"]), de(s["p_chi2"], 2)), "255"),
            ("Entropie je Byte", lambda s: de(s["entropy"], 4), "8"),
            ("Mittelwert", lambda s: de(s["mean"], 2), "127,5"),
            ("serielle Korrelation", lambda s: ("%+.4f" % s["scc"]).replace(".", ","), "0"),
            ("Monte-Carlo-π (Fehler)", lambda s: "%s (%s %%)" % (de(s["pi"], 4), de(abs(s["pi"] - 3.14159265) / 3.14159265 * 100, 2)), "3,1416"),
            ("Runs-Test z (p)", lambda s: "%s (%s)" % (("%+.2f" % s["z_runs"]).replace(".", ","), de(s["p_runs"], 2)), "0"),
            ("Bitpositionen außerhalb 3σ", lambda s: "%d von %d" % (s["outside3"], s["width"] * 8), "0,3 %"),
            ("größtes |r| (in σ)", lambda s: "%s (%s)" % (de(s["corr_worst"], 3), de(s["corr_worst"] / s["corr_sigma"], 1)), "≈ 3,5σ"),
            ("Hamming benachbarter Zeilen", lambda s: "%s ± %s" % (de(s["ham_mean"]), de(s["ham_sd"])), "½ Breite"),
        ]
        out_rows = []
        for name, fn, ideal in spec:
            out_rows.append("<tr><td>%s</td>%s<td class=\"num\">%s</td></tr>" % (
                name, "".join("<td class=\"num\">%s</td>" % fn(data[c]) for c in cols), ideal))
        return "".join(out_rows)

    cal = data["calibration"]
    calib_rows = "".join("<tr><td>%s</td><td class=\"num\">%s</td><td class=\"num\">%s</td></tr>" % (name, fn(cal["real"]), fn(cal["walker"]))
                         for name, fn in [
                             ("Wendungen je Sekunde", lambda c: de(c["rate"], 2)),
                             ("Samples zwischen Wendungen, Median", lambda c: "%d" % c["gap_median"]),
                             ("Streuung der Haltezeit (SD in log)", lambda c: de(c["gap_logsd"], 2)),
                             ("Wendungen um 45° / 90° / 135° / 180°", lambda c: " / ".join("%d %%" % v for v in c["steps"])),
                         ])

    real = by["sweep-full"]
    def at_rate(bits):
        return de(128 * real["seconds"] / bits, 0) + " s" if bits else "–"
    honest = (
        "Dieselben Stickverläufe, dreimal gezählt: Die alte Zählung brauchte im Median %s s (p10 %s, p90 %s), "
        "die erste Härtung %s s (p10 %s, p90 %s), die jetzige %s s (p10 %s, p90 %s). "
        "Die Aufzeichnung aus PPSSPP bekam in ihren %s s alt %d Bit, gehärtet %d, jetzt %d – im selben Tempo weiter "
        "%s, %s und %s bis zum vollen Balken. Die Härtung hatte den Takt der Hand verschenkt: Jetzt zählt auch, wann eine "
        "Wendung kommt, und das bringt einen ehrlichen Sweep ins Ziel, ohne die Muster wieder hereinzulassen."
    ) % (de(humans["old"]["median"]), de(humans["old"]["p10"]), de(humans["old"]["p90"]),
         de(humans["hard"]["median"]), de(humans["hard"]["p10"]), de(humans["hard"]["p90"]),
         de(hn["median"]), de(hn["p10"]), de(hn["p90"]),
         de(real["seconds"]), real["old_bits"], real["hard_bits"], real["new_bits"],
         at_rate(real["old_bits"]), at_rate(real["hard_bits"]), at_rate(real["new_bits"]))

    lazy = [r for r in table if r["kind"] == "cheap pattern"]
    never = sum(1 for r in lazy if r["new_full"] is None)
    finite = [r for r in lazy if r["new_full"] is not None]
    fastest = min(finite, key=lambda r: r["new_full"]) if finite else None
    cheap_before = min(r["old_full"] for r in lazy if r["old_full"] is not None)

    g = data["good"]
    b = data["broken_seeds"]
    pads = data["pads"]
    pad_rows = []
    for r in data["pad_table"]:
        label, sub = PAD_LABELS.get(r["name"], (r["name"], ""))
        if r["full"] is None:
            when, chip = "nie <span class=\"sub\">%d Bit in 600 s</span>" % r["bits"], '<span class="chip ok">hält</span>'
        else:
            when = de(r["full"]) + " s"
            chip = '<span class="chip ok">langsam</span>' if r["full"] > 2 * pads["masher"]["median"] else (
                '<span class="chip warn">Skript an der Decke</span>' if r["name"] == "lcg-buttons" else '<span class="chip warn">nah an einer Hand</span>')
        pad_rows.append("<tr><td><strong>%s</strong><span class=\"sub\">%s</span></td><td class=\"num\"><span class=\"after-v\">%s</span>%s</td><td class=\"num\">%d</td></tr>" % (
            label, sub, when, chip, r["paid_presses"]))
    pad_text = ("Median und Spanne (p10–p90); Stick allein aus %d Händen, die anderen Zeilen aus je %d Personen. Stick allein %s s (%s–%s), Knöpfe allein %s s (%s–%s, "
                "schnellster Sweep %s s), Stick und Knöpfe im Wechsel %s s (%s–%s). Grün hinterlegt das Ziel von 15 bis 19 Sekunden.") % (
        hn["n"], pads["masher"]["n"], de(hn["median"]), de(hn["p10"]), de(hn["p90"]),
        de(pads["masher"]["median"]), de(pads["masher"]["p10"]), de(pads["masher"]["p90"]), de(pads["masher"]["fastest"]),
        de(pads["mixed"]["median"]), de(pads["mixed"]["p10"]), de(pads["mixed"]["p90"]))
    steer = by.get("switcher-steer")
    repl = {
        "__CHEAP_BEFORE__": de(cheap_before),
        "__LAZY_AFTER__": "%d von %d nie" % (never, len(lazy)),
        "__LAZY_AFTER_SUB__": ("in 600 s; das schnellste der übrigen: %s, %s s" % (LABELS[fastest["name"]][0], de(fastest["new_full"])))
                              if fastest else "in 600 s",
        "__H_OLD__": de(humans["old"]["median"]),
        "__H_HARD__": de(humans["hard"]["median"]),
        "__H_NEW__": de(hn["median"]),
        "__H_N__": str(hn["n"]),
        "__N_OLD__": str(humans["old"]["finished"]),
        "__N_HARD__": str(humans["hard"]["finished"]),
        "__N_NEW__": str(hn["finished"]),
        "__TABLE__": "".join(rows),
        "__HONEST_TEXT__": honest,
        "__CALIB__": calib_rows,
        "__STEER__": de(steer["new_full"]) if steer and steer["new_full"] is not None else "nie",
        "__GOOD_N__": str(g["rows"]),
        "__GOOD_BYTES__": "{:,}".format(g["bytes"]).replace(",", "."),
        "__EXPECT__": de(g["bytes"] / 256, 0),
        "__CHI2__": de(g["chi2"]),
        "__PCHI__": de(g["p_chi2"], 2),
        "__SIGMA__": de(g["sigma"], 4),
        "__OUT3__": str(g["outside3"]),
        "__CORR__": de(g["corr_worst"], 3),
        "__CORRSIG__": de(g["corr_sigma"], 3),
        "__STATS_GOOD__": stat_rows(["good", "files"]),
        "__B2_REPRO__": "Byte für Byte gleich" if data["b2_reproducible"] else "verschieden",
        "__B_CHI2__": de(b["chi2"]),
        "__B_PCHI__": de(b["p_chi2"], 2),
        "__STATS_BROKEN__": stat_rows(["good", "broken_draws", "broken_seeds"]),
        "__SELFTEST__": data["selftest"].replace("&", "&amp;").replace("<", "&lt;"),
        "__PAD_TABLE__": "".join(pad_rows),
        "__PAD_MED__": de(pads["masher"]["median"]),
        "__PAD_TEXT__": pad_text,
    }
    page = PAGE
    for k, v in repl.items():
        page = page.replace(k, v)
    slim = dict(
        table=[{k: r[k] for k in ("name", "label", "seconds", "old_full", "hard_full", "new_full", "old_curve",
                                  "hard_curve", "new_curve", "path", "path_seconds", "credited", "old_credited") if k in r}
               for r in table],
        humans={k: dict(times=humans[k]["times"], median=humans[k]["median"], p90=humans[k]["p90"]) for k in ("old", "hard", "new")},
        pads={k: dict(times=pads[k]["times"], median=pads[k]["median"], p90=pads[k]["p90"]) for k in ("masher", "mixed")},
        good={k: g[k] for k in ("hist", "bytes", "bias", "sigma", "corr")},
        broken_seeds={k: b[k] for k in ("hist", "bytes")},
        bitmaps=data["bitmaps"],
    )
    page = page.replace("__DATA__", json.dumps(slim, separators=(",", ":")))
    with open(out, "w") as f:
        f.write(page)
    print("%s: %d KB" % (out, os.path.getsize(out) // 1024))
