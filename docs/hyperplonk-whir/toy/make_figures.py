#!/usr/bin/env python3
"""Generate the animated SVG figures used by OVERVIEW.md (stdlib only).

Run:  python3 -I docs/hyperplonk-whir/toy/make_figures.py
Writes docs/hyperplonk-whir/figures/*.svg. All numbers are recomputed here
(same arithmetic as toy_examples.py) so figures and text cannot drift.

Conventions: CSS-only animation (works inside <img> on GitHub), light/dark via
prefers-color-scheme, prefers-reduced-motion shows the final frame, and the
static (non-animated) state of every figure is its complete final frame.
Colours: reference data-viz palette (validated: 3 categorical slots, both modes).
"""
import math
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "figures")
P, Q = 97, 17

CSS_BASE = """
svg{--bg:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#9a9993;--grid:#e4e3df;--cell:#f0efec;
--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;--bad:#d03b3b;--good:#0ca30c;--t1:rgba(42,120,214,.16);--t2:rgba(235,104,52,.16)}
@media (prefers-color-scheme:dark){svg{--bg:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#77766f;--grid:#383835;
--cell:#262624;--s1:#3987e5;--s2:#d95926;--s3:#199e70;--bad:#e66767;--good:#0ca30c;--t1:rgba(57,135,229,.22);--t2:rgba(217,89,38,.22)}}
text{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;font-size:13px;fill:var(--ink);
font-variant-numeric:tabular-nums}
.t2{fill:var(--ink2)} .sm{font-size:11.5px} .lg{font-size:15px;font-weight:600} .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
.cell{fill:var(--cell);stroke:var(--grid);stroke-width:1}
.line{stroke:var(--muted);stroke-width:1.2;fill:none} .dash{stroke-dasharray:4 4}
.rv,.tr{animation-iteration-count:infinite;animation-fill-mode:both;animation-timing-function:ease-in-out}
.tr{opacity:0}
@media (prefers-reduced-motion:reduce){svg .rv,svg .tr{animation:none!important}svg .rv{opacity:1}svg .tr{opacity:0}svg .keep{opacity:1}}
"""


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Fig:
    def __init__(self, name, w, h, title, desc, steps, cycle):
        self.name, self.w, self.h, self.title, self.desc = name, w, h, title, desc
        self.steps, self.cycle, self.body, self.css = steps, cycle, [], []

    def reveal(self, k):
        """class for content that appears at step k (0..steps-1) and stays until the loop restarts."""
        a = 100 * k / self.steps * 0.9
        name = f"rv{k}"
        if k > 0 and name not in "".join(self.css):
            self.css.append(f"@keyframes {name}{{0%,{a:.1f}%{{opacity:0}}{a+2:.1f}%,97%{{opacity:1}}100%{{opacity:0}}}}"
                            f".{name}{{animation-name:{name};animation-duration:{self.cycle}s}}")
        return f"rv {name}" if k > 0 else ""

    def window(self, k, span=1):
        """class for transient content visible only during steps k..k+span-1."""
        a = 100 * k / self.steps * 0.9
        b = 100 * (k + span) / self.steps * 0.9
        name = f"tr{k}_{span}"
        if name not in "".join(self.css):
            self.css.append(f"@keyframes {name}{{0%,{a:.1f}%{{opacity:0}}{a+1.5:.1f}%,{b-1.5:.1f}%{{opacity:1}}{b:.1f}%,100%{{opacity:0}}}}"
                            f".{name}{{animation-name:{name};animation-duration:{self.cycle}s}}")
        return f"tr {name}"

    def add(self, s):
        self.body.append(s)

    def text(self, x, y, s, cls="", anchor="start", extra=""):
        self.add(f'<text x="{x}" y="{y}" class="{cls}" text-anchor="{anchor}" {extra}>{esc(s)}</text>')

    def write(self):
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" '
               f'role="img" aria-labelledby="title desc">\n<title id="title">{esc(self.title)}</title>\n'
               f'<desc id="desc">{esc(self.desc)}</desc>\n<style>{CSS_BASE}{"".join(self.css)}</style>\n'
               f'<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
               f'<path d="M0,0 L10,5 L0,10 z" fill="var(--muted)"/></marker>'
               f'<marker id="arrA" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
               f'<path d="M0,0 L10,5 L0,10 z" fill="var(--s1)"/></marker></defs>\n'
               f'<rect width="100%" height="100%" rx="10" fill="var(--bg)"/>\n' + "\n".join(self.body) + "\n</svg>\n")
        with open(os.path.join(OUT, self.name), "w") as f:
            f.write(svg)
        print("wrote", self.name)


def inv(a, p=P):
    return pow(a % p, p - 2, p)


# ------------------------------------------------------------------ 1. MLE fold
def fig_mle():
    T = [3, 1, 4, 1]
    r1, r2 = 2, 3
    a = [((1 - r1) * T[0] + r1 * T[2]) % P, ((1 - r1) * T[1] + r1 * T[3]) % P]
    v = ((1 - r2) * a[0] + r2 * a[1]) % P
    f = Fig("mle-fold.svg", 700, 300, "Multilinear extension: evaluating by folding",
            f"Table T=(3,1,4,1) on the square {{0,1}}^2, folded at X1=2 to ({a[0]},{a[1]}) and at X2=3 to {v}, mod 97.",
            4, 12)
    X = lambda x1: 80 + 90 * x1
    Y = lambda x2: 250 - 55 * x2
    f.text(20, 26, "Evaluate the multilinear extension of T at (2, 3) over F₉₇, one variable at a time", "lg")
    f.add(f'<line x1="{X(0)}" y1="{Y(0)}" x2="{X(2.4)}" y2="{Y(0)}" class="line" marker-end="url(#arr)"/>')
    f.add(f'<line x1="{X(0)}" y1="{Y(0)}" x2="{X(0)}" y2="{Y(3.5)}" class="line" marker-end="url(#arr)"/>')
    f.text(X(2.4) + 6, Y(0) + 4, "X₁", "t2")
    f.text(X(0) - 6, Y(3.5) - 4, "X₂", "t2", "end")
    for t in (0, 1, 2):
        f.text(X(t), Y(0) + 30, str(t), "t2 sm", "middle")
    for t in (0, 1, 2, 3):
        f.text(X(0) - 22, Y(t) + 4, str(t), "t2 sm", "end")
    f.add(f'<rect x="{X(0)}" y="{Y(1)}" width="{X(1)-X(0)}" height="{Y(0)-Y(1)}" fill="none" stroke="var(--ink2)" stroke-width="1.5"/>')
    pts = {(0, 0): T[0], (0, 1): T[1], (1, 0): T[2], (1, 1): T[3]}
    for (x1, x2), val in pts.items():
        f.add(f'<circle cx="{X(x1)}" cy="{Y(x2)}" r="13" fill="var(--t1)" stroke="var(--s1)" stroke-width="2"/>')
        f.text(X(x1), Y(x2) + 4.5, str(val), "", "middle", 'font-weight="600"')
    c1 = f.reveal(1)
    f.add(f'<g class="{c1}">')
    for x2 in (0, 1):
        f.add(f'<line x1="{X(1)+13}" y1="{Y(x2)}" x2="{X(2)-13}" y2="{Y(x2)}" class="line dash"/>')
        f.add(f'<circle cx="{X(2)}" cy="{Y(x2)}" r="13" fill="var(--t2)" stroke="var(--s2)" stroke-width="2"/>')
        f.text(X(2), Y(x2) + 4.5, str(a[x2]), "", "middle", 'font-weight="600"')
    f.add('</g>')
    c2 = f.reveal(2)
    f.add(f'<g class="{c2}"><line x1="{X(2)}" y1="{Y(1)-13}" x2="{X(2)}" y2="{Y(3)+15}" class="line dash"/>'
          f'<circle cx="{X(2)}" cy="{Y(3)}" r="15" fill="var(--s3)" stroke="var(--s3)" stroke-width="2"/></g>')
    f.text(X(2), Y(3) + 4.5, str(v), c2, "middle", 'font-weight="700" fill="#fff" style="fill:#fff"')
    tx = 330
    f.text(tx, 70, "① the table: T[x₁x₂] for rows 00, 01, 10, 11", "")
    f.text(tx, 90, "   T = (3, 1, 4, 1)  — the 4 corners of the square", "t2 sm")
    f.text(tx, 125, "② fold X₁ = 2:  (1−2)·T[0x₂] + 2·T[1x₂]", c1)
    f.text(tx + 12, 145, f"x₂ = 0:  −3 + 8 = {a[0]}", "t2 sm " + c1)
    f.text(tx + 170, 145, f"x₂ = 1:  −1 + 2 = {a[1]}", "t2 sm " + c1)
    f.text(tx, 180, "③ fold X₂ = 3:  (1−3)·5 + 3·1 = −7", c2)
    f.text(tx, 200, f"   = {v} (mod 97)  =  value of the MLE at (2, 3)", "t2 sm " + c2)
    c3 = f.reveal(3)
    f.text(tx, 232, "Same result as Σ_b T[b]·eq(b, (2,3)), in 2 + 1 steps:", "sm " + c3)
    f.text(tx, 250, "this is gnark-crypto's MultiLin.Fold (X₁ = MSB first).", "t2 sm " + c3)
    f.write()


# --------------------------------------------------------------- 2. sumcheck
def fig_sumcheck():
    T = [2, 0, 1, 3, 1, 1, 0, 2]
    rs = [5, 7, 2]
    rows, claims, msgs = [T], [sum(T) % P], []
    cur = T
    for r in rs:
        h = len(cur) // 2
        s0, s1 = sum(cur[:h]) % P, sum(cur[h:]) % P
        nxt = [((1 - r) * cur[j] + r * cur[h + j]) % P for j in range(h)]
        msgs.append((s0, s1, r))
        claims.append(((1 - r) * s0 + r * s1) % P)
        rows.append(nxt)
        cur = nxt
    f = Fig("sumcheck.svg", 860, 430, "Sumcheck on a 3-variable table, round by round",
            "Each round the prover sends the sums of the X=0 and X=1 halves; the verifier checks they add up to the claim, "
            "picks r and both fold the table; the last value is checked with one evaluation.", 8, 20)
    f.text(20, 28, "Sumcheck: prove Σ T(x) = 10 over {0,1}³  (F₉₇, toy table)", "lg")
    cw, x0, y0, dy = 46, 30, 62, 92
    for i, row in enumerate(rows):
        cls = f.reveal(2 * i) if i else ""
        y = y0 + i * dy
        h = len(row) // 2
        f.add(f'<g class="{cls}">')
        for j, val in enumerate(row):
            fill = "var(--t1)" if (j < h and len(row) > 1) else ("var(--t2)" if len(row) > 1 else "var(--cell)")
            f.add(f'<rect x="{x0+j*cw}" y="{y}" width="{cw-4}" height="34" rx="4" fill="{fill}" stroke="var(--grid)"/>')
            f.text(x0 + j * cw + (cw - 4) / 2, y + 22, str(val), "", "middle")
        if len(row) > 1:
            f.text(x0 + (h * cw) / 2 - 2, y - 6, f"X{['₁','₂','₃'][i]} = 0", "t2 sm", "middle")
            f.text(x0 + h * cw + (h * cw) / 2 - 2, y - 6, f"X{['₁','₂','₃'][i]} = 1", "t2 sm", "middle")
        lab = "claim" if i == 0 else f"new claim s{['₁','₂','₃'][i-1]}(r{['₁','₂','₃'][i-1]})"
        f.text(x0 + 8 * cw + 18, y + 22, f"{lab} = {claims[i]}", "")
        f.add('</g>')
        if i < len(rs):
            s0, s1, r = msgs[i]
            c = f.reveal(2 * i + 1)
            yy = y + 34 + 26
            f.text(x0 + 8 * cw + 18, yy - 4,
                   f"prover sends s(0) = {s0}, s(1) = {s1};  verifier: {s0} + {s1} = {claims[i]} ✓", "t2 sm " + c)
            f.text(x0 + 8 * cw + 18, yy + 13,
                   f"verifier picks r = {r};  fold: (1−r)·left + r·right", "t2 sm " + c)
            nh = len(row) // 2
            f.add(f'<g class="{c}">')
            for j in range(nh):
                tx = x0 + j * cw + (cw - 4) / 2
                for src in (j, j + nh):
                    sx = x0 + src * cw + (cw - 4) / 2
                    f.add(f'<line x1="{sx}" y1="{y+35}" x2="{tx}" y2="{y+dy-2}" class="line" stroke-opacity=".55"/>')
            f.add('</g>')
    c = f.reveal(7)
    yl = y0 + 3 * dy + 60
    f.text(x0, yl, f"End: the verifier needs one value, T̃(5, 7, 2) = {rows[-1][0]} — it equals the last claim ✓. "
                   "In HyperPlonk this value comes from a PCS opening.", "sm " + c)
    f.text(x0, yl + 20, "Cost: the prover's table halves every round (8 → 4 → 2 → 1); the verifier does O(1) work per round.",
           "t2 sm " + c)
    f.write()


# --------------------------------------------------------------- 3. circuit
def fig_circuit():
    n = 4
    sel = [("−1", "0", "0", "0", "0"), ("0", "0", "−1", "1", "0"), ("1", "1", "−1", "0", "0"), ("1", "−1", "0", "0", "5")]
    W = [[("17", "out"), ("3", "x"), ("9", "v₁"), ("12", "v₂")],
         [("17", "out"), ("3", "x"), ("3", "x"), ("17", "out")],
         [("17", "out"), ("9", "v₁"), ("12", "v₂"), ("17", "out")]]
    meaning = ["public: −w₀ + pub₀ = 0", "x·x − v₁ = 0", "v₁ + x − v₂ = 0", "v₂ − out + 5 = 0"]
    cycles = [("out (wire 0)", [0, 4, 8, 7, 11]), ("x", [1, 5, 6]), ("v₁", [9, 2]), ("v₂", [10, 3])]
    f = Fig("circuit.svg", 900, 420, "Toy circuit x² + x + 5 = out as a HyperPlonk table with its copy cycles",
            "Four rows: public placeholder, x*x=v1, v1+x=v2, v2+5=out. The permutation sigma links every cell holding the "
            "same variable into a cycle; the animation highlights the cycles of out, x, v1 and v2 in turn.", 5, 16)
    f.text(20, 28, "Toy circuit  x² + x + 5 = out  with x = 3 (secret), out = 17 (public), over F₉₇", "lg")
    hdr = ["row", "q_L", "q_R", "q_O", "q_M", "q_C", "w₀ (L)", "w₁ (R)", "w₂ (O)", "constraint"]
    xs = [30, 80, 125, 170, 215, 260, 320, 410, 500, 600]
    y0, dy = 70, 52
    for x, hname in zip(xs, hdr):
        f.text(x, y0 - 12, hname, "t2 sm")
    center = {}
    for i in range(n):
        y = y0 + i * dy
        f.text(xs[0] + 8, y + 26, str(i), "t2")
        for k, s in enumerate(sel[i]):
            f.text(xs[1 + k] + 10, y + 26, s, "", "middle")
        for j in range(3):
            x = xs[6 + j]
            f.add(f'<rect x="{x}" y="{y+4}" width="78" height="38" rx="5" class="cell"/>')
            f.text(x + 39, y + 21, W[j][i][0], "", "middle", 'font-weight="600"')
            f.text(x + 39, y + 36, W[j][i][1], "t2 sm", "middle")
            center[j * n + i] = (x + 39, y + 23)
        f.text(xs[9], y + 26, meaning[i], "t2 sm")
    for k, (name, cyc) in enumerate(cycles):
        cls = f.window(k, 1) + (" keep" if name == "x" else "")
        f.add(f'<g class="{cls}">')
        for a, b in zip(cyc, cyc[1:] + cyc[:1]):
            (x1, y1), (x2, y2) = center[a], center[b]
            mx, my = (x1 + x2) / 2 + (y2 - y1) * 0.25 + 18, (y1 + y2) / 2 - (x2 - x1) * 0.25
            f.add(f'<path d="M{x1},{y1} Q{mx},{my} {x2},{y2}" fill="none" stroke="var(--s1)" stroke-width="2.2" '
                  f'marker-end="url(#arrA)" stroke-opacity=".9"/>')
        labels = " → ".join(f"(w{c//n},{c%n})" for c in cyc) + f" → (w{cyc[0]//n},{cyc[0]%n})"
        f.text(30, y0 + 4 * dy + 30, f"σ-cycle of {name}:  {labels}", "", extra='style="fill:var(--ink)"')
        f.add('</g>')
    c = f.reveal(4)
    f.text(30, y0 + 4 * dy + 58, "Copy constraint = \"w is constant along every σ-cycle\". Position (column j, row i) has label "
                                 "id = j·n + i; σ maps it to the next position of the same variable.", "t2 sm " + c)
    f.text(30, y0 + 4 * dy + 76, "Unused R/O cells hold wire 0 (= the first public variable, here out) — gnark's padding "
                                 "convention — so they join out's cycle.", "t2 sm " + c)
    f.write()


# ------------------------------------------------------------- 4. RS queries
def fig_rs():
    L = [pow(2, i, Q) for i in range(8)]
    cw = [(3 + 2 * x) % Q for x in L]
    bad = cw[:]
    for pos in (1, 4, 6):
        bad[pos] = 0
    seq = [2, 6, 0, 5, 1, 7]
    f = Fig("rs-queries.svg", 820, 350, "Reed-Solomon codeword vs a corrupted word, and random spot checks",
            "f(X)=3+2X evaluated on the 8-element subgroup <2> of F17 (rate 1/4); a word differing in 3 positions; "
            "queries land on random positions and catch the cheater when they hit a corrupted one.", len(seq) + 1, 14)
    f.text(20, 28, "Reed–Solomon: f(X) = 3 + 2X on L = ⟨2⟩ ⊂ F₁₇  (8 points, degree < 2, rate ρ = 2/8)", "lg")
    x0, w, y1, y2 = 150, 70, 70, 150
    f.text(20, y1 + 24, "codeword f(L)", "t2")
    f.text(20, y2 + 24, "committed word", "t2")
    for i, x in enumerate(L):
        f.text(x0 + i * w + 32, y1 - 10, f"x = {x}", "t2 sm", "middle")
        f.add(f'<rect x="{x0+i*w}" y="{y1}" width="64" height="38" rx="5" class="cell"/>')
        f.text(x0 + i * w + 32, y1 + 24, str(cw[i]), "", "middle")
        isbad = bad[i] != cw[i]
        stroke = "var(--bad)" if isbad else "var(--grid)"
        f.add(f'<rect x="{x0+i*w}" y="{y2}" width="64" height="38" rx="5" class="cell" style="stroke:{stroke};stroke-width:{2 if isbad else 1}"/>')
        f.text(x0 + i * w + 32, y2 + 24, str(bad[i]) + ("  ✗" if isbad else ""), "", "middle")
    f.text(x0, y2 + 60, "3 of 8 positions differ (✗). Two distinct codewords differ in ≥ 1 − ρ = 75 % of positions,", "t2 sm")
    f.text(x0, y2 + 76, "so the word is far from every codeword — a few random spot checks expose it.", "t2 sm")
    for k, pos in enumerate(seq):
        cls = f.window(k, 1)
        hit = bad[pos] != cw[pos]
        cx = x0 + pos * w + 32
        f.add(f'<g class="{cls}"><path d="M{cx-9},{y2+112} L{cx+9},{y2+112} L{cx},{y2+96} z" fill="var(--s1)"/>'
              f'<rect x="{x0+pos*w-3}" y="{y1-3}" width="70" height="{y2-y1+44}" rx="7" fill="none" stroke="var(--s1)" stroke-width="2.5"/>')
        f.text(cx, y2 + 130, f"query {k+1}: x = {L[pos]} → " + ("✗ mismatch — rejected" if hit else "✓ agrees"),
               "sm", "middle", 'font-weight="600"')
        f.add('</g>')
    c = f.reveal(len(seq))
    f.text(x0, y2 + 156, "Each query misses every ✗ with probability 5/8; t queries all miss with (5/8)ᵗ:", "sm " + c)
    f.text(x0, y2 + 174, "15 queries → below 2⁻¹⁰. WHIR's query counts come from the same rule (§6.4).", "t2 sm " + c)
    f.write()


# ---------------------------------------------------------- 5. interleaved RS
def fig_irs():
    L = [pow(2, i, Q) for i in range(8)]
    v = [3, 1, 4, 1]
    c0 = [(v[0] + v[1] * x) % Q for x in L]
    c1 = [(v[2] + v[3] * x) % Q for x in L]
    alpha, xq = 5, 4
    fv = [((1 - alpha) * v[0] + alpha * v[2]) % Q, ((1 - alpha) * v[1] + alpha * v[3]) % Q]
    j = L.index(xq)
    folded = ((1 - alpha) * c0[j] + alpha * c1[j]) % Q
    f = Fig("interleaved-rs.svg", 860, 360, "WHIR's interleaved Reed-Solomon encoding and leaf folding",
            "Table v=(3,1,4,1) split into two chunks, each encoded on L; a Merkle leaf is one column; folding a leaf with "
            "alpha=5 gives the encoding of the folded table at that point.", 4, 14)
    f.text(20, 28, "WHIR encoding (toy: m = 2, k = 1, F₁₇):  table → chunks → codewords → Merkle leaves", "lg")
    f.text(20, 66, f"table v = (3, 1, 4, 1)  →  chunk₀ = (3, 1) ↦ ĉ₀(X) = 3 + X,   chunk₁ = (4, 1) ↦ ĉ₁(X) = 4 + X", "")
    x0, w, ya = 150, 74, 110
    c = f.reveal(1)
    f.add(f'<g class="{c}">')
    f.text(20, ya + 24, "ĉ₀ on L", "t2")
    f.text(20, ya + 70, "ĉ₁ on L", "t2")
    for i, x in enumerate(L):
        f.text(x0 + i * w + 34, ya - 8, f"x = {x}", "t2 sm", "middle")
        for r, row in enumerate((c0, c1)):
            f.add(f'<rect x="{x0+i*w}" y="{ya+r*46}" width="68" height="38" rx="5" class="cell"/>')
            f.text(x0 + i * w + 34, ya + r * 46 + 24, str(row[i]), "", "middle")
    f.add('</g>')
    c = f.reveal(2)
    f.add(f'<g class="{c}"><rect x="{x0+j*w-4}" y="{ya-4}" width="76" height="92" rx="8" fill="none" stroke="var(--s1)" stroke-width="2.5"/></g>')
    f.text(x0 + j * w + 34, ya + 108, "one Merkle leaf", "sm " + c, "middle", 'style="fill:var(--ink)"')
    f.text(x0, ya + 140, f"A leaf holds every chunk at the same x. The verifier opens leaf x = {xq}: ({c0[j]}, {c1[j]}).",
           "t2 sm " + c)
    c = f.reveal(3)
    f.text(x0, ya + 175, f"Fold with α = {alpha}:  (1−α)·{c0[j]} + α·{c1[j]} = {folded} (mod 17)", "sm " + c,
           extra='font-weight="600"')
    f.text(x0, ya + 195, f"Check: the folded table P(α, ·) = ({fv[0]}, {fv[1]}) encodes to {fv[0]} + {fv[1]}·x = "
                         f"{(fv[0]+fv[1]*xq)%Q} at x = {xq}  ✓ — so one leaf lets the verifier fold by itself.", "t2 sm " + c)
    f.text(x0, ya + 215, "Real parameters: k = 4 (16 chunks per leaf), ρ = 1/8, |L₀| = 2^(m−4)·8.", "t2 sm " + c)
    f.write()


# ------------------------------------------------------------ 6. WHIR rounds
def fig_whir():
    rounds = [(18, 14, 17, 90), (14, 10, 16, 44), (10, 6, 15, 29)]
    f = Fig("whir-rounds.svg", 860, 380, "WHIR rounds for the W opening at 2^16 rows (estimate)",
            "Log-scale bars: per round the message (chunk length) shrinks 16x while the domain only halves, so the rate "
            "drops 8x per round and fewer queries are needed: 90, 44, 29 (estimates, lambda 128, Johnson regime).", 5, 14)
    f.text(20, 28, "Why later WHIR rounds are cheap: W opening at 2¹⁶ rows (m = 18, k = 4, ρ₀ = 1/8)", "lg")
    x0, sc, y0, dy = 190, 30, 90, 62
    for t in range(0, 19, 2):
        x = x0 + t * sc
        f.add(f'<line x1="{x}" y1="{y0-14}" x2="{x}" y2="{y0+3*dy+8}" stroke="var(--grid)" stroke-width="1"/>')
        f.text(x, y0 + 3 * dy + 24, f"2^{t}", "t2 sm", "middle")
    f.text(x0 + 9 * sc, y0 + 3 * dy + 42, "size (log₂ scale)", "t2 sm", "middle")
    for i, (m, chunk, dom, q) in enumerate(rounds):
        cls = f.reveal(i)
        y = y0 + i * dy
        f.add(f'<g class="{cls}">')
        f.text(20, y + 14, f"round {i}: table 2^{m}", "")
        f.text(20, y + 31, f"rate 2^-{dom-chunk},  {q} queries", "t2 sm")
        f.add(f'<rect x="{x0}" y="{y}" width="{dom*sc}" height="16" rx="4" fill="var(--s2)"/>')
        f.add(f'<rect x="{x0}" y="{y+20}" width="{chunk*sc}" height="16" rx="4" fill="var(--s1)"/>')
        f.text(x0 + dom * sc + 6, y + 13, f"codeword 2^{dom}", "sm")
        f.text(x0 + chunk * sc + 6, y + 33, f"chunk (message) 2^{chunk}", "sm")
        f.add('</g>')
    c = f.reveal(3)
    f.text(20, y0 + 3 * dy - 6, "base case: 2⁶ = 64 values sent", "sm " + c)
    c = f.reveal(4)
    f.text(20, y0 + 3 * dy + 66, "Each round: k = 4 sumcheck rounds shrink the table 16×, the new codeword's domain only halves → "
                                 "rate falls 8× → each query is worth more bits.", "t2 sm " + c)
    f.text(20, y0 + 3 * dy + 84, "Query counts are estimates (λ = 128, Johnson regime); the real table comes from whirparams (M0b).",
           "t2 sm " + c)
    f.add('<rect x="20" y="44" width="12" height="12" rx="3" fill="var(--s2)"/>')
    f.text(38, 54, "codeword (evaluation domain)", "sm")
    f.add('<rect x="240" y="44" width="12" height="12" rx="3" fill="var(--s1)"/>')
    f.text(258, 54, "message chunk (2^(m−k) coefficients)", "sm")
    f.write()


# --------------------------------------------------------------- 7. ZK mask
def fig_mask():
    f = Fig("zk-mask.svg", 760, 360, "Witness mask: same values on the hypercube, random elsewhere",
            "Real-number illustration: w(t)=2+3t and masked versions w(t)+c*t*(1-t) for c=-6, 4, 9. All agree at t=0 and "
            "t=1 (the hypercube), and differ at the random point t=rho1.", 3, 12)
    f.text(20, 28, "w*(X) = w(X) + c·X₁(1−X₁): the constraints only see X₁ ∈ {0,1}, the verifier sees X₁ = ρ₁", "lg")
    x0, y0, W_, H_ = 70, 300, 600, 240
    tmin, tmax, vmin, vmax = -0.4, 1.8, -6, 14
    X = lambda t: x0 + (t - tmin) / (tmax - tmin) * W_
    Y = lambda v: y0 - (v - vmin) / (vmax - vmin) * H_
    for v in range(-4, 15, 4):
        f.add(f'<line x1="{x0}" y1="{Y(v)}" x2="{x0+W_}" y2="{Y(v)}" stroke="var(--grid)"/>')
        f.text(x0 - 8, Y(v) + 4, str(v), "t2 sm", "end")
    for t in (0, 1):
        f.add(f'<line x1="{X(t)}" y1="{Y(vmin)}" x2="{X(t)}" y2="{Y(vmax)}" stroke="var(--grid)" stroke-dasharray="3 3"/>')
        f.text(X(t), y0 + 18, f"X₁ = {t}", "t2 sm", "middle")
    rho = 1.5
    f.add(f'<line x1="{X(rho)}" y1="{Y(vmin)}" x2="{X(rho)}" y2="{Y(vmax)}" stroke="var(--ink2)" stroke-dasharray="6 3"/>')
    f.text(X(rho), y0 + 18, "X₁ = ρ₁ (random)", "sm", "middle")
    w = lambda t: 2 + 3 * t
    pts = lambda fn: " ".join(f"{X(t):.1f},{Y(fn(t)):.1f}" for t in [tmin + i * (tmax - tmin) / 80 for i in range(81)])
    f.add(f'<polyline points="{pts(w)}" fill="none" stroke="var(--ink2)" stroke-width="2"/>')
    f.text(X(0.62), Y(w(0.62)) + 22, "w (unmasked)", "t2 sm", "middle")
    for k, c in enumerate((-6, 4, 9)):
        cls = f.window(k, 1) + (" keep" if c == 4 else "")
        fn = lambda t, c=c: w(t) + c * t * (1 - t)
        f.add(f'<g class="{cls}"><polyline points="{pts(fn)}" fill="none" stroke="var(--s1)" stroke-width="2.5"/>'
              f'<circle cx="{X(rho)}" cy="{Y(fn(rho))}" r="6" fill="var(--s1)" stroke="var(--bg)" stroke-width="2"/></g>')
        f.text(X(rho) + 14, Y(fn(rho)) + 4, f"c = {c}: w*(ρ₁) = {fn(rho):.2f}", "sm " + cls)
    for t in (0, 1):
        f.add(f'<circle cx="{X(t)}" cy="{Y(w(t))}" r="6" fill="var(--s3)" stroke="var(--bg)" stroke-width="2"/>')
    f.text(X(0) - 10, Y(w(0)) - 10, "same on {0,1}", "sm", "end")
    f.text(x0, 52, "Real numbers for the picture; in F the offset c·ρ₁(1−ρ₁) is uniform when c is, so w*(ρ) reveals nothing.",
           "t2 sm")
    f.write()


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for fn in (fig_mle, fig_sumcheck, fig_circuit, fig_rs, fig_irs, fig_whir, fig_mask):
        fn()
