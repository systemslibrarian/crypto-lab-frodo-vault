// ============================================================================
// Frodo Vault — Educational FrodoKEM Demonstration
// ============================================================================
//
// Exhibits 2–4 run REAL, vetted FrodoKEM (and ML-KEM-768 for the hybrid),
// compiled to WebAssembly from liboqs via @oqs/liboqs-js. Key generation,
// encapsulation, decapsulation, tamper-rejection, the timing benchmark, and the
// hybrid derivation are all genuine cryptographic operations — see frodo-kem.ts.
//
// What is REAL:  FrodoKEM keygen/encaps/decaps (liboqs WASM), parameter sizes,
//                LWE math, noise distributions, in-browser timing measurements
// What is TOY:   The first-principles LWE solver (n=3, q=97) and the q=17
//                decryption-failure model in Exhibits 1 and 5 — intentionally
//                small so the math is solvable by hand and fully visualizable
//
// FrodoKEM parameter sets sourced from math.ts are spec-accurate:
//   FrodoKEM-640  (n=640),  FrodoKEM-976  (n=976),  FrodoKEM-1344 (n=1344)
// ============================================================================

import './style.css';
import {
  type LweSample,
  type FrodoId,
  type FrodoParams,
  FRODO,
  mod,
  vecDot,
  solve3x3Mod97,
  buildToyLweSamples,
  normalPdfLike,
  computeFailureProbabilities,
  formatHex,
  hexPreview,
  concat,
  renderCtDiff,
} from './math';
import { getFrodoKem, getMlKem768, bytesEqual, statsMs } from './frodo-kem';

type TabId = 'lwe' | 'keygen' | 'kem' | 'compare' | 'errors' | 'landscape' | 'divide';

const TABS: TabId[] = ['lwe', 'keygen', 'kem', 'compare', 'errors', 'landscape', 'divide'];

type OpStats = { median: number; min: number; max: number };
type SchemeStats = { keygen: OpStats; encaps: OpStats; decaps: OpStats; loadMs: number };
type CompareStats = { samples: number; warmup: number; frodo: SchemeStats; mlkem: SchemeStats };

// ── Teaching spine ──────────────────────────────────────────────────────────
// Each exhibit answers one learner question (shown at the top) and closes with a
// short "you should now understand" recall summary (shown at the bottom).
const OBJECTIVES: Record<TabId, string> = {
  lwe: 'Why does adding a little error make easy linear algebra hard?',
  keygen: 'Where do A, S, E, and B show up in a real FrodoKEM keypair — and why is it so big?',
  kem: 'How do two parties derive the same secret without ever sending it?',
  compare: 'What does FrodoKEM actually pay — in bytes and milliseconds — to avoid ring structure?',
  errors: 'Why must the error be small enough to decode yet random enough to hide the secret?',
  landscape: 'If FrodoKEM is so conservative, why is it not the default KEM?',
  divide: 'Why do NIST and China disagree about whether to trust algebraic structure?',
};

const TAKEAWAYS: Record<TabId, string[]> = {
  lwe: [
    'Without noise, (a, b) pairs are a solvable linear system — Gaussian elimination recovers s exactly.',
    'Add small errors and the equations become mutually inconsistent; no exact solution survives. That gap is the LWE hardness.',
  ],
  keygen: [
    'A real keypair is B = A·S + E mod q, published as (seedA, B); A is regenerated from the seed, never stored.',
    'Key size grows directly with n and the matrix shape — that is the price of plain (unstructured) LWE.',
  ],
  kem: [
    'Only the public key and the ciphertext cross the wire; the secret key and the shared secret never do.',
    'Both sides derive the same shared secret from the math — a tampered ciphertext makes decapsulation return an unrelated implicit-rejection secret, so the round-trip fails.',
  ],
  compare: [
    'FrodoKEM trades ~13× larger keys and slower operations for a smaller, structure-free assumption.',
    'The ratio between the two schemes is the durable lesson; the raw millisecond numbers depend on your device.',
  ],
  errors: [
    'Errors must stay well inside ±q/4-ish bounds so the message still decodes — too big and decryption fails.',
    'They must also be drawn from a wide enough distribution to hide s; correctness and security pull in opposite directions.',
  ],
  landscape: [
    'FrodoKEM is the conservative, structure-free option — valuable for long-horizon secrets, not for bandwidth-constrained defaults.',
    'ML-KEM (FIPS 203) is the standard default; hybrids let you hedge with both.',
  ],
  divide: [
    'Structured lattices (ML-KEM) are fast but carry an extra algebraic attack surface the base LWE proof does not cover.',
    'Both NIST (HQC backup) and China (structureless S-Cloud+) are hedging the same uncertainty in different ways.',
  ],
};

// Prediction checkpoints: predict-before-reveal prompts for active recall.
type Checkpoint = {
  id: string;
  prompt: string;
  options: Array<{ value: string; label: string }>;
  correct: string;
  explain: string;
};
const CHECKPOINTS: Record<string, Checkpoint> = {
  'lwe-clean': {
    id: 'lwe-clean',
    prompt: 'Predict: with no noise (e = 0), will Gaussian elimination recover the secret exactly?',
    options: [
      { value: 'yes', label: 'Yes, exactly' },
      { value: 'no', label: 'No, only approximately' },
    ],
    correct: 'yes',
    explain: 'With e = 0 the samples are an ordinary linear system over Z₉₇, so elimination recovers s exactly. Noise is the only thing that makes LWE hard.',
  },
  'lwe-noisy': {
    id: 'lwe-noisy',
    prompt: 'Predict: with noise added, will the secret you solve from the first 3 equations satisfy the other samples?',
    options: [
      { value: 'yes', label: 'Yes, they will all agree' },
      { value: 'no', label: 'No, they become inconsistent' },
    ],
    correct: 'no',
    explain: 'Each sample carries its own error, so a secret fit to three noisy equations leaves nonzero residuals on the rest. That inconsistency is exactly what hides s.',
  },
  'kem-tamper': {
    id: 'kem-tamper',
    prompt: 'Predict: after you flip one ciphertext bit, will Alice still recover Bob’s exact shared secret?',
    options: [
      { value: 'yes', label: 'Yes — one bit is harmless' },
      { value: 'no', label: 'No — she gets a different secret' },
    ],
    correct: 'no',
    explain: 'FrodoKEM’s Fujisaki–Okamoto transform re-encapsulates during decapsulation; a single changed bit fails the check, so it returns an unrelated implicit-rejection secret instead of throwing.',
  },
  compare: {
    id: 'compare',
    prompt: 'Predict before benchmarking: which scheme has the larger public key, and which is faster?',
    options: [
      { value: 'frodo-big-mlkem-fast', label: 'FrodoKEM bigger key, ML-KEM faster' },
      { value: 'same', label: 'Roughly the same on both' },
      { value: 'frodo-fast', label: 'FrodoKEM bigger key but also faster' },
    ],
    correct: 'frodo-big-mlkem-fast',
    explain: 'FrodoKEM-976’s public key (~15.6 KB) dwarfs ML-KEM-768’s (~1.2 KB), and its unstructured matrix multiply is markedly slower than ML-KEM’s NTT. Size and speed both pay for avoiding ring structure.',
  },
  'errors-failure': {
    id: 'errors-failure',
    prompt: 'Predict: as the error magnitude approaches q/2, what happens to decryption?',
    options: [
      { value: 'fine', label: 'Stays correct' },
      { value: 'fails', label: 'Failure rate climbs sharply' },
    ],
    correct: 'fails',
    explain: 'Once errors can push an encoded bit past the halfway decision boundary, decoding flips and correctness collapses — the failure curve has a sharp cliff, which is why real parameters keep σ small.',
  },
};

const GLOSSARY: Array<{ term: string; def: string }> = [
  { term: 'KEM', def: 'Key Encapsulation Mechanism — a way for two parties to agree on a shared secret using public-key cryptography.' },
  { term: 'LWE', def: 'Learning With Errors — recovering a secret from noisy linear equations mod q; believed hard even for quantum computers.' },
  { term: 'Plain LWE', def: 'LWE over an unstructured random matrix A (FrodoKEM). No ring/module algebra, so no extra structural attack surface.' },
  { term: 'Ring-/Module-LWE', def: 'LWE over structured polynomial rings (ML-KEM). Faster and smaller, but adds algebraic structure the base proof does not cover.' },
  { term: 'Ciphertext (ct)', def: 'The encapsulation output sent to the key owner; lets them derive the shared secret. The secret itself is never sent.' },
  { term: 'Shared secret (SS)', def: 'The symmetric key both parties end up with. Derived independently on each side — not transmitted.' },
  { term: 'Encapsulation', def: 'Using a public key to produce a ciphertext and a shared secret.' },
  { term: 'Decapsulation', def: 'Using a secret key and a ciphertext to recover the same shared secret.' },
  { term: 'Implicit rejection', def: 'On an invalid ciphertext, FrodoKEM returns a pseudo-random secret instead of an error — leaking nothing about why it failed.' },
  { term: 'CCA security (IND-CCA2)', def: 'Security even against an attacker who can request decapsulations of chosen ciphertexts.' },
  { term: 'KDF', def: 'Key Derivation Function — hashes inputs into a uniform key (here used to combine hybrid secrets).' },
  { term: 'WASM', def: 'WebAssembly — a portable binary format; liboqs is compiled to WASM so real FrodoKEM runs in your browser.' },
];

const MISCONCEPTIONS: Array<{ wrong: string; right: string }> = [
  { wrong: '“FrodoKEM is simply more secure than ML-KEM.”', right: 'It rests on a more conservative assumption (plain LWE), but it is not the NIST default and is not automatically the better choice for a given deployment.' },
  { wrong: '“No ring structure means no mathematical structure at all.”', right: 'It still has lattice/LWE structure — it only avoids the ring/module algebraic structure that NTT-based schemes exploit.' },
  { wrong: '“The shared secret is sent inside the ciphertext.”', right: 'The ciphertext lets the recipient derive the same secret. The secret itself never crosses the wire.' },
  { wrong: '“A browser demo using real crypto is production-safe.”', right: 'Real primitives are not a secure protocol or key-management system. Constant-time guarantees, key storage, and protocol design all still matter.' },
  { wrong: '“A tampered ciphertext failing means FrodoKEM authenticates the sender.”', right: 'KEM validity is not sender authentication. It only means invalid ciphertexts do not reveal useful key material.' },
];

function tabFromHash(): TabId | null {
  const h = location.hash.replace('#', '');
  return TABS.includes(h as TabId) ? (h as TabId) : null;
}

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('App root not found');
const appRoot = app;

const state = {
  activeTab: (tabFromHash() ?? 'lwe') as TabId,
  selectedParam: 'frodo976' as FrodoId,
  lweSecret: [3, 7, 11] as [number, number, number],
  lweSamples: [] as LweSample[],
  lweCleanSamples: [] as LweSample[],
  lweOutcome: 'Generate toy LWE samples, then test solving with and without noise.',
  keygenPreview: '',
  keygenSkSize: 0,
  keygenMs: 0,
  keygenRatio: '',
  keygenBusy: false,
  kemParamId: null as FrodoId | null,
  kemAlicePk: null as Uint8Array | null,
  kemAliceSk: null as Uint8Array | null,
  kemCiphertext: null as Uint8Array | null,
  kemBobSecret: null as Uint8Array | null,
  kemAliceSecret: null as Uint8Array | null,
  kemEncapMs: 0,
  kemDecapMs: 0,
  kemBusy: false,
  kemStatus: 'Generate Alice keypair to begin encapsulation.',
  kemPreTamperCt: null as Uint8Array | null,
  compareBench: '',
  compareBusy: false,
  compareStats: null as CompareStats | null,
  errorHistogram: [] as Array<{ value: number; count: number }>,
  errorSummary: 'Sample 1000 errors to visualize FrodoKEM-style discrete distribution.',
  failureSummary: 'Run the toy decryption-failure demo (n=4, q=17) with oversized errors.',
  lweNoiseMag: 1,
  failProbs: [] as Array<{ maxErr: number; rate: number }>,
  matrixAnimHtml: '',
  matrixAnimRunning: false,
  hybridFrodoSS: null as Uint8Array | null,
  hybridMlkemSS: null as Uint8Array | null,
  hybridCombinedSS: null as Uint8Array | null,
  hybridBusy: false,
  hybridStatus: 'Run the hybrid demo to derive a combined shared secret.',
  openCollapsibles: new Set<string>(),
  // Prediction checkpoints: maps a checkpoint id to the learner's chosen answer.
  predictions: {} as Record<string, string>,
};

function randomUint32(): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0];
}

function randomInt(maxExclusive: number): number {
  if (maxExclusive <= 0) return 0;
  return randomUint32() % maxExclusive;
}

function randomFromRange(min: number, max: number): number {
  return min + randomInt(max - min + 1);
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digestInput = new Uint8Array(data.byteLength);
  digestInput.set(data);
  const digest = await crypto.subtle.digest('SHA-256', digestInput);
  return new Uint8Array(digest);
}

// Lets the browser paint a pending "Working…" state before we run a burst of
// synchronous WASM work (keygen/encaps/decaps block the main thread for a bit).
function yieldToPaint(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function sampleDiscreteError(maxAbs: number, sigma: number): number {
  const values: number[] = [];
  const weights: number[] = [];
  let total = 0;
  for (let v = -maxAbs; v <= maxAbs; v += 1) {
    const w = normalPdfLike(v, sigma);
    values.push(v);
    weights.push(w);
    total += w;
  }
  const r = (randomUint32() / 0xffffffff) * total;
  let running = 0;
  for (let i = 0; i < values.length; i += 1) {
    running += weights[i];
    if (r <= running) return values[i];
  }
  return 0;
}

function generateHistogram(param: FrodoParams): Array<{ value: number; count: number }> {
  const map = new Map<number, number>();
  for (let i = -param.maxError; i <= param.maxError; i += 1) {
    map.set(i, 0);
  }
  for (let i = 0; i < 1000; i += 1) {
    const sample = sampleDiscreteError(param.maxError, param.sigma);
    map.set(sample, (map.get(sample) ?? 0) + 1);
  }
  return Array.from(map.entries()).map(([value, count]) => ({ value, count }));
}

function runFailureDemo(): string {
  const q = 17;
  const half = Math.floor(q / 2); // 8
  let tries = 0;
  while (tries < 25) {
    tries += 1;
    const m = randomInt(2);
    const accumulatedError = randomFromRange(-6, 6);
    const noisy = mod(m * half + accumulatedError, q);

    const dist0 = Math.min(mod(noisy, q), mod(-noisy, q));
    const dist1 = Math.min(mod(noisy - half, q), mod(half - noisy, q));
    const recovered = dist1 < dist0 ? 1 : 0;

    if (recovered !== m) {
      return `Toy failure observed: message=${m}, encoded=${noisy} mod ${q}, accumulated error=${accumulatedError}, recovered=${recovered}. Oversized errors break correctness.`;
    }
  }
  return 'No failure occurred in 25 tries. Re-run: oversized errors still cause frequent failures at toy scale.';
}

async function runMatrixAnimation(): Promise<void> {
  const container = document.getElementById('matrix-anim-container');
  if (!container) return;
  state.matrixAnimRunning = true;

  const q = 97;
  const s = state.lweSecret;
  const rows = 3;
  const A: number[][] = [];
  const errors: number[] = [];
  const results: number[] = [];

  for (let i = 0; i < rows; i++) {
    A.push([randomFromRange(0, q - 1), randomFromRange(0, q - 1), randomFromRange(0, q - 1)]);
    const e = randomFromRange(-state.lweNoiseMag, state.lweNoiseMag);
    errors.push(e);
    results.push(mod(A[i][0] * s[0] + A[i][1] * s[1] + A[i][2] * s[2] + e, q));
  }

  function renderMatrix(activeRow: number, activeCol: number, computed: number[]): string {
    let html = '<div class="matrix-viz">';
    html += '<div class="matrix-label">A · s + e = b mod 97</div>';
    html += '<div style="display:grid;grid-template-columns:auto auto auto;gap:0.5rem;align-items:center">';
    html += '<div>';
    for (let r = 0; r < rows; r++) {
      html += '<div class="matrix-row">';
      for (let c = 0; c < 3; c++) {
        const cls = r === activeRow && c === activeCol ? 'active' : (r < activeRow ? 'result' : '');
        html += `<div class="matrix-cell ${cls}">${A[r][c]}</div>`;
      }
      html += '</div>';
    }
    html += '</div>';
    html += '<div style="text-align:center">·<br>';
    for (let c = 0; c < 3; c++) {
      const cls = c === activeCol && activeRow >= 0 ? 'active' : '';
      html += `<div class="matrix-cell ${cls}">${s[c]}</div>`;
    }
    html += '</div>';
    html += '<div style="text-align:center">=<br>';
    for (let r = 0; r < rows; r++) {
      if (r < computed.length) {
        html += `<div class="matrix-cell result">${computed[r]}</div>`;
      } else {
        html += '<div class="matrix-cell">?</div>';
      }
    }
    html += '</div></div>';
    if (activeRow >= 0 && activeRow < rows) {
      const terms = A[activeRow].map((a, c) => `${a}·${s[c]}`);
      html += `<div class="matrix-equation">${terms.join(' + ')} + (${errors[activeRow]}) = ${results[activeRow]} mod ${q}</div>`;
    } else if (computed.length === rows) {
      html += '<div class="matrix-equation">Complete! All b values computed.</div>';
    }
    html += '</div>';
    return html;
  }

  const computed: number[] = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < 3; c++) {
      if (!container.isConnected) { state.matrixAnimRunning = false; return; }
      container.innerHTML = renderMatrix(r, c, computed);
      await new Promise(res => setTimeout(res, 300));
    }
    computed.push(results[r]);
    if (!container.isConnected) { state.matrixAnimRunning = false; return; }
    container.innerHTML = renderMatrix(r, -1, computed);
    await new Promise(res => setTimeout(res, 400));
  }
  if (!container.isConnected) { state.matrixAnimRunning = false; return; }
  container.innerHTML = renderMatrix(-1, -1, computed);
  state.matrixAnimHtml = container.innerHTML;
  state.matrixAnimRunning = false;
}

function renderObjective(tab: TabId): string {
  return `<p class="objective"><span class="objective-tag">Goal</span> ${OBJECTIVES[tab]}</p>`;
}

// Bridges the conceptual slice in Exhibit 1 to the real scheme, so learners don't
// mistake the n=3 toy for a miniature of all of FrodoKEM's internals.
function renderToyRealBridge(): string {
  const rows: Array<[string, string]> = [
    ['n = 3 (three unknowns)', 'n = 640, 976, or 1344'],
    ['q = 97', 'q = 2¹⁵ or 2¹⁶'],
    ['one secret vector s', 'secret matrix S with n × n̄ entries'],
    ['a single random row a', 'a huge n × n matrix A, expanded from a 16-byte seed'],
    ['b = ⟨a, s⟩ + e', 'B = A·S + E mod q'],
    ['solvable by hand', 'a full-size LWE instance — believed quantum-hard'],
    ['e ∈ {−1, 0, 1}, uniform', 'discrete Gaussian-like errors, table-sampled'],
  ];
  return `<article class="card">
    <h3>From this toy to real FrodoKEM</h3>
    <p>Exhibit 1 is a <em>conceptual slice</em>, not a shrunk-down FrodoKEM. Here is exactly what each toy symbol becomes at full scale (Exhibits 2–4 run the right column for real):</p>
    <div class="table-wrap">
      <table class="bridge-table">
        <caption class="sr-only">Mapping from the toy LWE demo to real FrodoKEM</caption>
        <thead><tr><th scope="col">Toy LWE demo (this exhibit)</th><th scope="col">Real FrodoKEM</th></tr></thead>
        <tbody>${rows.map(([t, r]) => `<tr><td>${t}</td><td>${r}</td></tr>`).join('')}</tbody>
      </table>
    </div>
  </article>`;
}

function renderTakeaway(tab: TabId): string {
  return `<article class="card takeaway">
    <h3>✓ You should now understand</h3>
    <ul>${TAKEAWAYS[tab].map((t) => `<li>${t}</li>`).join('')}</ul>
  </article>`;
}

function renderCheckpoint(id: string): string {
  const cp = CHECKPOINTS[id];
  if (!cp) return '';
  const answered = state.predictions[id];
  const opts = cp.options
    .map((o) => {
      const chosen = answered === o.value;
      const cls = answered ? (o.value === cp.correct ? 'cp-correct' : chosen ? 'cp-wrong' : '') : '';
      return `<button class="cp-option ${cls}" type="button" data-checkpoint="${id}" data-choice="${o.value}" ${answered ? 'disabled' : ''} aria-pressed="${chosen}">${o.label}</button>`;
    })
    .join('');
  const feedback = answered
    ? `<p class="cp-feedback ${answered === cp.correct ? 'ok' : 'off'}" role="status">${answered === cp.correct ? '✓ Correct.' : '↪ Not quite —'} ${cp.explain}</p>`
    : '';
  return `<div class="checkpoint" role="group" aria-label="Prediction checkpoint">
    <p class="cp-prompt"><span class="cp-tag">Predict</span> ${cp.prompt}</p>
    <div class="cp-options">${opts}</div>
    ${feedback}
  </div>`;
}

function fmtOp(op: 'keygen' | 'encaps' | 'decaps', scheme: 'frodo' | 'mlkem'): string {
  const s = state.compareStats;
  if (!s) return '--';
  const o = s[scheme][op];
  return `${o.median.toFixed(3)} ms <span class="op-range">(${o.min.toFixed(3)}–${o.max.toFixed(3)})</span>`;
}

function renderGlossary(): string {
  const open = state.openCollapsibles.has('glossary');
  return `<article class="card glossary">
    <button class="collapsible-toggle" aria-expanded="${open}" data-collapse="glossary">Glossary — key terms</button>
    <div class="collapsible-body ${open ? 'open' : ''}" id="glossary">
      <dl class="glossary-list">${GLOSSARY.map(
        (g) => `<div class="glossary-item"><dt>${g.term}</dt><dd>${g.def}</dd></div>`,
      ).join('')}</dl>
    </div>
  </article>`;
}

function renderMisconceptions(): string {
  return `<section class="misconceptions-panel" aria-label="Common misconceptions">
    <h2>Common Misconceptions</h2>
    <div class="misconception-grid">${MISCONCEPTIONS.map(
      (m) => `<div class="misconception"><p class="mc-wrong">${m.wrong}</p><p class="mc-right">${m.right}</p></div>`,
    ).join('')}</div>
  </section>`;
}

// Compact stateful data-flow diagram for the KEM exhibit. Highlights the step
// just completed so learners can see what crosses the wire and what stays private.
function renderKemFlow(): string {
  const hasKeys = state.kemAlicePk !== null;
  const hasCt = state.kemCiphertext !== null;
  const hasAlice = state.kemAliceSecret !== null;
  const tampered = state.kemPreTamperCt !== null;
  const step = (on: boolean) => (on ? 'on' : '');
  const match = hasAlice && state.kemBobSecret ? bytesEqual(state.kemAliceSecret!, state.kemBobSecret) : null;
  const wireCls = tampered ? 'wire tampered' : 'wire';
  return `<div class="kem-flow" role="img" aria-label="KEM data flow: Alice publishes a public key, Bob returns a ciphertext, both derive the same shared secret; only the public key and ciphertext cross the wire.">
    <div class="flow-party">
      <div class="flow-role">Alice</div>
      <div class="flow-item ${step(hasKeys)}">holds sk <span class="flow-private">private</span></div>
      <div class="flow-item ${step(hasKeys)}">publishes pk</div>
      <div class="flow-item ${step(hasAlice)}">derives SS<sub>A</sub>${match === null ? '' : match ? ' ✓' : ' ✗'}</div>
    </div>
    <div class="flow-wire">
      <div class="${wireCls}"><span>pk →</span></div>
      <div class="${wireCls}"><span>← ct${tampered ? ' (tampered)' : ''}</span></div>
      <div class="flow-note">only pk &amp; ct cross the wire</div>
    </div>
    <div class="flow-party">
      <div class="flow-role">Bob</div>
      <div class="flow-item ${step(hasCt)}">uses pk</div>
      <div class="flow-item ${step(hasCt)}">sends ct</div>
      <div class="flow-item ${step(hasCt)}">derives SS<sub>B</sub> <span class="flow-private">private</span></div>
    </div>
  </div>`;
}

function render(): void {
  const params = FRODO[state.selectedParam];
  const histMax = Math.max(1, ...state.errorHistogram.map((h) => h.count));
  const kemMatch =
    state.kemAliceSecret && state.kemBobSecret
      ? formatHex(state.kemAliceSecret) === formatHex(state.kemBobSecret)
      : false;

  appRoot.innerHTML = `
  <main id="main-content" class="shell">
    <div class="hero-header">
      <p class="eyebrow">crypto-lab demo</p>
      <h1>Frodo Vault: FrodoKEM without ring structure</h1>
      <p class="subhead">Learn why FrodoKEM chooses plain LWE, watch real liboqs FrodoKEM run in your browser, and see the exact cost — in bytes and milliseconds — of avoiding ring structure.</p>
    </div>

    <div class="disclaimer-banner" role="note">
      <strong>Educational demo running real FrodoKEM.</strong> Exhibits 2\u20134 perform genuine FrodoKEM (and ML-KEM-768) operations via liboqs compiled to WebAssembly. It is a learning tool, not a key-management system: keys are ephemeral, in-memory, and never reused \u2014 don't use it to secure real data. <a href="#references">Sources &amp; references \u2192</a>
    </div>

    <nav class="tabs" role="tablist" aria-label="FrodoKEM exhibits">
      <button class="tab ${state.activeTab === 'lwe' ? 'active' : ''}" data-tab="lwe" role="tab" id="tab-lwe" aria-selected="${state.activeTab === 'lwe'}" aria-controls="panel-lwe">1. LWE Problem</button>
      <button class="tab ${state.activeTab === 'keygen' ? 'active' : ''}" data-tab="keygen" role="tab" id="tab-keygen" aria-selected="${state.activeTab === 'keygen'}" aria-controls="panel-keygen">2. Key Generation</button>
      <button class="tab ${state.activeTab === 'kem' ? 'active' : ''}" data-tab="kem" role="tab" id="tab-kem" aria-selected="${state.activeTab === 'kem'}" aria-controls="panel-kem">3. Encap / Decap</button>
      <button class="tab ${state.activeTab === 'compare' ? 'active' : ''}" data-tab="compare" role="tab" id="tab-compare" aria-selected="${state.activeTab === 'compare'}" aria-controls="panel-compare">4. Frodo vs ML-KEM</button>
      <button class="tab ${state.activeTab === 'errors' ? 'active' : ''}" data-tab="errors" role="tab" id="tab-errors" aria-selected="${state.activeTab === 'errors'}" aria-controls="panel-errors">5. Error Distribution</button>
      <button class="tab ${state.activeTab === 'landscape' ? 'active' : ''}" data-tab="landscape" role="tab" id="tab-landscape" aria-selected="${state.activeTab === 'landscape'}" aria-controls="panel-landscape">6. PQ Landscape</button>
      <button class="tab ${state.activeTab === 'divide' ? 'active' : ''}" data-tab="divide" role="tab" id="tab-divide" aria-selected="${state.activeTab === 'divide'}" aria-controls="panel-divide">7. The Global Divide</button>
    </nav>
    <p class="kbd-hint" aria-hidden="true">Navigate: <kbd>←</kbd> <kbd>→</kbd> arrow keys</p>

    ${renderGlossary()}

    <section class="panel ${state.activeTab === 'lwe' ? 'visible' : ''}" id="panel-lwe" role="tabpanel" aria-labelledby="tab-lwe" ${state.activeTab !== 'lwe' ? 'hidden' : ''}>
      ${renderObjective('lwe')}
      <article class="card">
        <h2>Learning With Errors (LWE) from first principles <span class="badge badge-real">Real math</span></h2>
        <p>LWE was introduced by Regev (2005)<sup class="cite"><a href="#ref-1">[1]</a></sup>. Given noisy linear equations over Z<sub>q</sub>, recover secret vector s.</p>
        <p>Formal sample: pick random a ∈ Z<sub>q</sub><sup>n</sup>, compute b = &lt;a, s&gt; + e mod q with small error e. Given many (a,b), recover s.</p>
        <p>Without noise this is linear algebra; with noise, equations become inconsistent and decoding is hard.</p>
        <blockquote>Educational LWE — toy parameters, not production. Toy interactive demo uses n=3, q=97, and e ∈ {-1, 0, 1}.</blockquote>
        <details class="reality-panel">
          <summary>Reality check — this exhibit</summary>
          <div class="reality-content">
            <div class="reality-row"><span class="reality-badge">✅ Real</span><span>The LWE problem definition and modular arithmetic are mathematically correct<sup class="cite"><a href="#ref-1">[1]</a></sup>. Gaussian elimination over Z<sub>q</sub> is genuine linear algebra.</span></div>
            <div class="reality-row"><span class="reality-badge">⚠️ Simplified</span><span>Toy dimension n=3, modulus q=97 (vs production n≥640, q≥2<sup>15</sup>). Error sampling is uniform, not discrete Gaussian.</span></div>
            <div class="reality-row"><span class="reality-badge">🚫 Not guaranteed</span><span>No cryptographic security at toy scale. A 3×3 system can be solved by hand.</span></div>
          </div>
        </details>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Interactive toy LWE demo</h3>
          <div class="controls">
            <span>s =</span>
            <label class="sr-only" for="s0">Secret s[0]</label>
            <input id="s0" type="number" min="0" max="96" value="${state.lweSecret[0]}" aria-label="Secret s[0]" />
            <label class="sr-only" for="s1">Secret s[1]</label>
            <input id="s1" type="number" min="0" max="96" value="${state.lweSecret[1]}" aria-label="Secret s[1]" />
            <label class="sr-only" for="s2">Secret s[2]</label>
            <input id="s2" type="number" min="0" max="96" value="${state.lweSecret[2]}" aria-label="Secret s[2]" />
          </div>
          <div class="controls">
            <button id="rand-secret">Random secret</button>
            <button id="gen-samples">Generate 5 LWE samples</button>
            <button id="solve-clean">Solve without noise</button>
            <button id="solve-noisy">Solve with noise</button>
          </div>
          <div class="noise-slider-wrap">
            <label for="noise-mag">Error magnitude: <strong>${state.lweNoiseMag}</strong></label>
            <input id="noise-mag" type="range" min="0" max="48" value="${state.lweNoiseMag}" />
            <span>${state.lweNoiseMag === 0 ? 'No noise' : state.lweNoiseMag <= 3 ? 'Small (solvable)' : state.lweNoiseMag <= 12 ? 'Medium (hard)' : 'Large (impossible)'}</span>
          </div>
          <p role="status" aria-live="polite">${state.lweOutcome}</p>
          ${renderCheckpoint('lwe-clean')}
          ${renderCheckpoint('lwe-noisy')}
        </div>
        <div>
          <button class="collapsible-toggle" aria-expanded="${state.openCollapsibles.has('lwe-detail')}" data-collapse="lwe-detail">Ring-LWE vs plain LWE</button>
          <div class="collapsible-body ${state.openCollapsibles.has('lwe-detail') ? 'open' : ''}" id="lwe-detail">
          <ul>
            <li>Plain LWE (FrodoKEM): A is a random n×n matrix, no ring structure.</li>
            <li>Ring/Module-LWE (ML-KEM): structured polynomial algebra gives faster and smaller operations.</li>
            <li>FrodoKEM design choice: keep only the plain LWE assumption.</li>
          </ul>
          <p>Historical context: Regev (2005), Ring-LWE by Lyubashevsky-Peikert-Regev (2010), FrodoKEM (2016) "Take off the ring".</p>
          </div>
        </div>
      </article>

      <article class="card table-wrap">
        <h3>Generated samples (a, b)</h3>
        <table>
          <caption class="sr-only">LWE sample equations</caption>
          <thead><tr><th scope="col">#</th><th scope="col">a</th><th scope="col">b</th><th scope="col">error e</th></tr></thead>
          <tbody>
            ${state.lweSamples
              .map(
                (row, i) => `<tr><td>${i + 1}</td><td>[${row.a.join(', ')}]</td><td>${row.b}</td><td>${row.e}</td></tr>`,
              )
              .join('')}
          </tbody>
        </table>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> LWE underlies much of modern post-quantum KEM design. Removing ring structure increases conservatism at significant size cost.
      </article>

      <article class="card">
        <h3>Animated: A·s + e = b mod q</h3>
        <p>Watch each row of A multiplied by secret s, then error e added. This is how each LWE sample is computed.</p>
        <button id="run-matrix-anim" ${state.matrixAnimRunning ? 'disabled' : ''}>Animate A·s + e</button>
        <div id="matrix-anim-container">${state.matrixAnimHtml}</div>
      </article>

      ${renderToyRealBridge()}

      ${renderTakeaway('lwe')}
    </section>

    <section class="panel ${state.activeTab === 'keygen' ? 'visible' : ''}" id="panel-keygen" role="tabpanel" aria-labelledby="tab-keygen" ${state.activeTab !== 'keygen' ? 'hidden' : ''}>
      ${renderObjective('keygen')}
      <article class="card">
        <h2>FrodoKEM key generation <span class="badge badge-real">Real · liboqs WASM</span></h2>
        <p>Each click runs the genuine flow inside liboqs: seed → expand A (AES/SHAKE), sample S and E from the noise distribution, compute B = A·S + E mod q, publish (seed<sub>A</sub>, B)<sup class="cite"><a href="#ref-4">[4]</a></sup>.</p>
        <p>For FrodoKEM-976, n=976 and n̄=8. A full 976×976 matrix of 16-bit values would be about 1.9MB, so only seed<sub>A</sub> is stored.</p>
        <div class="controls">
          <label for="param-select">Parameter set</label>
          <select id="param-select" ${state.keygenBusy ? 'disabled' : ''}>
            <option value="frodo640" ${state.selectedParam === 'frodo640' ? 'selected' : ''}>FrodoKEM-640</option>
            <option value="frodo976" ${state.selectedParam === 'frodo976' ? 'selected' : ''}>FrodoKEM-976</option>
            <option value="frodo1344" ${state.selectedParam === 'frodo1344' ? 'selected' : ''}>FrodoKEM-1344</option>
          </select>
          <button id="run-keygen" ${state.keygenBusy ? 'disabled' : ''}>${state.keygenBusy ? 'Generating…' : 'Generate keypair'}</button>
        </div>
        <details class="reality-panel">
          <summary>Reality check — this exhibit</summary>
          <div class="reality-content">
            <div class="reality-row"><span class="reality-badge">✅ Real</span><span>The keypair is generated by real FrodoKEM (liboqs, compiled to WebAssembly): A is expanded from seed<sub>A</sub> and B = A·S + E mod q is actually computed<sup class="cite"><a href="#ref-4">[4]</a></sup>. The previewed bytes and the private-key size are real outputs, and they match the spec sizes exactly.</span></div>
            <div class="reality-row"><span class="reality-badge">⚠️ In-browser</span><span>Generation time depends on your device and the WASM JIT, so it is slower than a native build. The first run also downloads the algorithm's WASM module.</span></div>
            <div class="reality-row"><span class="reality-badge">🚫 Not for production</span><span>Keys live only in this page's memory and are never persisted, reused, or exposed to a real peer. This is a teaching UI, not a key-management system.</span></div>
          </div>
        </details>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Real FrodoKEM sizes</h3>
          <div class="table-wrap">
            <table>
              <caption class="sr-only">FrodoKEM parameter sizes</caption>
              <thead><tr><th scope="col">Set</th><th scope="col">Public key</th><th scope="col">Private key</th><th scope="col">Security</th></tr></thead>
              <tbody>
                <tr><td>FrodoKEM-640</td><td>9,616 bytes</td><td>19,888 bytes</td><td>~103-bit PQ</td></tr>
                <tr><td>FrodoKEM-976</td><td>15,632 bytes</td><td>31,296 bytes</td><td>~150-bit PQ</td></tr>
                <tr><td>FrodoKEM-1344</td><td>21,520 bytes</td><td>43,088 bytes</td><td>~207-bit PQ</td></tr>
              </tbody>
            </table>
          </div>
          <p>Generated public key preview: <code>${state.keygenPreview || '--'}</code></p>
          <p>Private key size: ${state.keygenSkSize || '--'} bytes</p>
          <p>Generation time: ${state.keygenMs ? `${state.keygenMs.toFixed(3)} ms` : '--'}</p>
          <p>${state.keygenRatio || ''}</p>
        </div>
        <div>
          <h3>Public key size bar chart</h3>
          <div class="bar-group">
            <div class="bar-line">
              <strong>ML-KEM-768: 1,184 bytes</strong>
              <div class="bar-track"><div class="bar-fill" style="--w: ${((1184 / params.publicKey) * 100).toFixed(1)}%;"></div></div>
            </div>
            <div class="bar-line">
              <strong>${params.label}: ${params.publicKey.toLocaleString()} bytes</strong>
              <div class="bar-track"><div class="bar-fill" style="--w: 100%;"></div></div>
            </div>
          </div>
          <p>Ratio: ${params.label} public key is about ${(params.publicKey / 1184).toFixed(1)}× larger than ML-KEM-768.</p>
        </div>
      </article>

      <article class="card">
        <h3>Why are FrodoKEM keys so large?</h3>
        <p>Each key's byte count derives directly from the matrix dimensions<sup class="cite"><a href="#ref-4">[4]</a></sup>:</p>
        <div class="size-calc"><span class="calc-label">pk</span> = seed_A + B matrix = 16 + n × n̄ × ⌈log₂(q)⌉/8
<span class="calc-label">${params.label}:</span> 16 + ${params.n} × 8 × ${Math.ceil(Math.log2(params.q))}/8 = <span class="calc-result">${params.publicKey.toLocaleString()} bytes ✓</span>

<span class="calc-label">sk</span> = s + pk + S matrix + pkh
<span class="calc-label">${params.label}:</span> ${params.n <= 640 ? 16 : params.n <= 976 ? 24 : 32} + ${params.publicKey.toLocaleString()} + ${params.n} × 8 × 2 + ${params.n <= 640 ? 16 : params.n <= 976 ? 24 : 32} = <span class="calc-result">${params.privateKey.toLocaleString()} bytes ✓</span>

<span class="calc-label">ct</span> = c1 + c2 = (n̄ × n × D/8) + (n̄ × n̄ × D/8)
<span class="calc-label">${params.label}:</span> ${(8 * params.n * Math.ceil(Math.log2(params.q)) / 8).toLocaleString()} + ${(8 * 8 * Math.ceil(Math.log2(params.q)) / 8).toLocaleString()} = <span class="calc-result">${params.ciphertext.toLocaleString()} bytes ✓</span></div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> Large keys are the price of avoiding ring/module structure. For high-value long-term secrets, this tradeoff can be acceptable.
      </article>

      ${renderTakeaway('keygen')}
    </section>

    <section class="panel ${state.activeTab === 'kem' ? 'visible' : ''}" id="panel-kem" role="tabpanel" aria-labelledby="tab-kem" ${state.activeTab !== 'kem' ? 'hidden' : ''}>
      ${renderObjective('kem')}
      <article class="card">
        <h2>Encapsulation and decapsulation <span class="badge badge-real">Real · liboqs WASM</span></h2>
        <p>Encapsulation (run for real): sample S′, E′, E″, compute B′ = A·S′ + E′ and V = B·S′ + E″, encode a random message, output ciphertext (B′, C), derive the shared secret via KDF<sup class="cite"><a href="#ref-4">[4]</a></sup>.</p>
        <p>Decapsulation (run for real): compute W = B′·S, recover the message, re-encapsulate to validate, and derive the same shared secret.</p>
        <div class="controls">
          <button id="kem-gen" ${state.kemBusy ? 'disabled' : ''}>1 · Generate Alice keypair</button>
          <button id="kem-encap" ${state.kemBusy ? 'disabled' : ''}>2 · Bob encapsulates</button>
          <button id="kem-decap" ${state.kemBusy ? 'disabled' : ''}>3 · Alice decapsulates</button>
          <button id="kem-tamper" ${state.kemBusy ? 'disabled' : ''}>Tamper with ciphertext</button>
        </div>
        <p role="status" aria-live="polite">${state.kemStatus}</p>
        ${renderKemFlow()}
        ${renderCheckpoint('kem-tamper')}
        <details class="reality-panel">
          <summary>Reality check — this exhibit</summary>
          <div class="reality-content">
            <div class="reality-row"><span class="reality-badge">✅ Real</span><span>Keygen, encapsulation, and decapsulation are real FrodoKEM (liboqs/WASM). Alice's and Bob's secrets match because the LWE math agrees<sup class="cite"><a href="#ref-4">[4]</a></sup> — not because of any hash trick. The ciphertext is genuine LWE-encrypted data of the spec size.</span></div>
            <div class="reality-row"><span class="reality-badge">✅ Real tamper test</span><span>Flipping a ciphertext bit triggers FrodoKEM's IND-CCA2 implicit rejection: decapsulation returns an unrelated secret, so the round-trip genuinely fails — the mismatch is cryptographic, not cosmetic.</span></div>
            <div class="reality-row"><span class="reality-badge">🚫 Not for production</span><span>No constant-time or side-channel guarantees in this in-browser context, and keys/secrets are ephemeral and never leave the page. Use liboqs/PQClean directly to secure real data.</span></div>
          </div>
        </details>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Ciphertext and secret</h3>
          <p>Ciphertext preview: <code>${state.kemCiphertext ? hexPreview(state.kemCiphertext, 64) : '--'}</code></p>
          <p>Bob shared secret${state.kemBobSecret ? ` (${state.kemBobSecret.length} bytes)` : ''}: <code>${state.kemBobSecret ? formatHex(state.kemBobSecret) : '--'}</code></p>
          <p>Alice shared secret${state.kemAliceSecret ? ` (${state.kemAliceSecret.length} bytes)` : ''}: <code>${state.kemAliceSecret ? formatHex(state.kemAliceSecret) : '--'}</code></p>
          <p>Encapsulation time: ${state.kemEncapMs ? `${state.kemEncapMs.toFixed(3)} ms` : '--'}</p>
          <p>Decapsulation time: ${state.kemDecapMs ? `${state.kemDecapMs.toFixed(3)} ms` : '--'}</p>
          ${state.kemPreTamperCt ? `<div class="ct-diff">${renderCtDiff(state.kemPreTamperCt, state.kemCiphertext)}</div>` : ''}
          <p class="${kemMatch ? 'status-ok' : 'status-bad'}">${
            state.kemAliceSecret && state.kemBobSecret
              ? kemMatch
                ? '✓ Secrets match'
                : '✗ Secrets mismatch'
              : '--'
          }</p>
        </div>
        <div>
          <h3>Real ciphertext sizes</h3>
          <table>
            <caption class="sr-only">FrodoKEM ciphertext sizes</caption>
            <thead><tr><th scope="col">Parameter set</th><th scope="col">Ciphertext</th></tr></thead>
            <tbody>
              <tr><td>FrodoKEM-640</td><td>9,720 bytes</td></tr>
              <tr><td>FrodoKEM-976</td><td>15,744 bytes</td></tr>
              <tr><td>FrodoKEM-1344</td><td>21,632 bytes</td></tr>
            </tbody>
          </table>
          <p>ML-KEM-768 ciphertext: 1,088 bytes.</p>
        </div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> FrodoKEM-976 ciphertext is about 15KB. For infrequent, high-value key exchanges this overhead is often acceptable.
      </article>

      ${renderTakeaway('kem')}
    </section>

    <section class="panel ${state.activeTab === 'compare' ? 'visible' : ''}" id="panel-compare" role="tabpanel" aria-labelledby="tab-compare" ${state.activeTab !== 'compare' ? 'hidden' : ''}>
      ${renderObjective('compare')}
      <article class="card">
        <h2>FrodoKEM vs ML-KEM: conservative choice <span class="badge badge-real">Real · measured here</span></h2>
        <p>Size and security data below are from published specifications<sup class="cite"><a href="#ref-3">[3]</a></sup><sup class="cite"><a href="#ref-4">[4]</a></sup>. The timing rows are <strong>measured on your device</strong> — warm-up runs first, then the median (and min–max range) of real liboqs WASM keygen/encaps/decaps runs.</p>
        ${renderCheckpoint('compare')}
        <button id="run-compare" ${state.compareBusy ? 'disabled' : ''}>${state.compareBusy ? 'Benchmarking…' : 'Run real benchmark (FrodoKEM-976 vs ML-KEM-768)'}</button>
        <p role="status" aria-live="polite">${state.compareBench}</p>
        ${state.compareStats ? `<p class="bench-method">Method: ${state.compareStats.warmup} warm-up run(s) discarded, then ${state.compareStats.samples} measured samples per operation. One-time WASM load (excluded from op timings): FrodoKEM-976 ${state.compareStats.frodo.loadMs.toFixed(0)} ms, ML-KEM-768 ${state.compareStats.mlkem.loadMs.toFixed(0)} ms.</p>` : ''}
        <details class="reality-panel">
          <summary>Reality check — this exhibit</summary>
          <div class="reality-content">
            <div class="reality-row"><span class="reality-badge">✅ Real</span><span>Key sizes, ciphertext sizes, security levels, and NIST status are from published specifications<sup class="cite"><a href="#ref-3">[3]</a></sup><sup class="cite"><a href="#ref-4">[4]</a></sup>. The timing rows are genuine measurements of the real liboqs WASM operations running in your browser.</span></div>
            <div class="reality-row"><span class="reality-badge">⚠️ Device-dependent</span><span>Absolute milliseconds depend on your CPU, browser, and the WASM JIT, and a native build would be faster than this in-browser one. The <em>ratio</em> between the two schemes is the durable takeaway, not the raw numbers.</span></div>
            <div class="reality-row"><span class="reality-badge">🚫 Not a lab benchmark</span><span>For controlled cross-platform numbers, see the liboqs or PQClean benchmark suites.</span></div>
          </div>
        </details>
      </article>

      <article class="card table-wrap">
        <table>
          <caption class="sr-only">FrodoKEM-976 vs ML-KEM-768 comparison</caption>
          <thead>
            <tr><th scope="col">Property</th><th scope="col">FrodoKEM-976</th><th scope="col">ML-KEM-768</th></tr>
          </thead>
          <tbody>
            <tr><td>Hardness assumption</td><td>Plain LWE</td><td>Module-LWE (ring)</td></tr>
            <tr><td>Public key</td><td>15,632 bytes</td><td>1,184 bytes</td></tr>
            <tr><td>Ciphertext</td><td>15,744 bytes</td><td>1,088 bytes</td></tr>
            <tr><td>Shared secret</td><td>24 bytes</td><td>32 bytes</td></tr>
            <tr><td>Classical security</td><td>~192 bits</td><td>~192 bits</td></tr>
            <tr><td>PQ security</td><td>~150 bits</td><td>~178 bits</td></tr>
            <tr><td>Key generation <span class="sim-notice">measured here</span></td><td>${fmtOp('keygen', 'frodo')}</td><td>${fmtOp('keygen', 'mlkem')}</td></tr>
            <tr><td>Encapsulation <span class="sim-notice">measured here</span></td><td>${fmtOp('encaps', 'frodo')}</td><td>${fmtOp('encaps', 'mlkem')}</td></tr>
            <tr><td>Decapsulation <span class="sim-notice">measured here</span></td><td>${fmtOp('decaps', 'frodo')}</td><td>${fmtOp('decaps', 'mlkem')}</td></tr>
            <tr><td>NIST status</td><td>Round 4 alternate</td><td>FIPS 203 standard</td></tr>
            <tr><td>Ring structure</td><td>None</td><td>Module / ring</td></tr>
            <tr><td>Deployment</td><td>Niche, high-value</td><td>Default PQ KEM</td></tr>
          </tbody>
        </table>
      </article>

      <article class="card decision">
        <button class="collapsible-toggle" aria-expanded="${state.openCollapsibles.has('decision-tree')}" data-collapse="decision-tree">Decision tree</button>
        <div class="collapsible-body ${state.openCollapsibles.has('decision-tree') ? 'open' : ''}" id="decision-tree">
        <p>Post-quantum TLS or general use → <strong>ML-KEM-768</strong>.</p>
        <p>Maximum conservatism and size is acceptable → <strong>FrodoKEM-976</strong>.</p>
        <p>Archive secrecy horizon 20+ years → <strong>FrodoKEM-1344</strong>.</p>
        <p>Need smallest keys and fastest operation → <strong>ML-KEM-512</strong>.</p>
        <p>Maximum assurance recommendation: <code>SS = KDF(SS_mlkem || SS_frodo)</code>.</p>
        <p>Kyber Vault cross-link: <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener">https://systemslibrarian.github.io/crypto-lab-kyber-vault/</a></p>
        </div>
      </article>

      <article class="card">
        <h3>Hybrid KEM walkthrough <span class="badge badge-real">Real · liboqs WASM</span></h3>
        <p>Run two real encapsulations — ML-KEM-768 and FrodoKEM-976 — and combine their shared secrets with a KDF into one hybrid secret. With a sound, domain-separated combiner the result stays secure if <em>at least one</em> component KEM is secure.</p>
        <button id="run-hybrid" ${state.hybridBusy ? 'disabled' : ''}>${state.hybridBusy ? 'Deriving…' : 'Run hybrid KEM derivation'}</button>
        <p role="status" aria-live="polite">${state.hybridStatus}</p>
        <p class="bench-method">This demo uses <code>SHA-256(SS_mlkem ∥ SS_frodo)</code> for clarity; production deployments should use a specified hybrid combiner (e.g. per the relevant IETF/NIST guidance) rather than a bare concatenation hash.</p>
        ${state.hybridCombinedSS ? `
        <div class="hybrid-box">
          <div class="hybrid-secrets">
            <div>
              <strong>ML-KEM-768 SS:</strong><br>
              <code>${formatHex(state.hybridMlkemSS)}</code>
            </div>
            <div>
              <strong>FrodoKEM-976 SS:</strong><br>
              <code>${formatHex(state.hybridFrodoSS)}</code>
            </div>
          </div>
          <div>
            <strong>Hybrid SS = KDF(SS_mlkem || SS_frodo):</strong><br>
            <span class="hybrid-final">${formatHex(state.hybridCombinedSS)}</span>
          </div>
        </div>` : ''}
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> Ring-LWE risk remains theoretical, not a known break. FrodoKEM is explicit insurance against future structural breakthroughs.
      </article>

      ${renderTakeaway('compare')}
    </section>

    <section class="panel ${state.activeTab === 'errors' ? 'visible' : ''}" id="panel-errors" role="tabpanel" aria-labelledby="tab-errors" ${state.activeTab !== 'errors' ? 'hidden' : ''}>
      ${renderObjective('errors')}
      <article class="card">
        <h2>Error distribution: where security lives <span class="badge badge-real">Real sampling</span></h2>
        <p>FrodoKEM uses discrete table-sampled errors approximating Gaussian behavior<sup class="cite"><a href="#ref-4">[4]</a></sup>. Errors must be random enough for security and small enough for correctness.</p>
        <div class="controls">
          <button id="sample-errors">Sample 1000 errors</button>
          <button id="run-failure">Run toy decryption failure</button>
          <button id="run-fail-chart">Failure probability chart</button>
        </div>
        ${renderCheckpoint('errors-failure')}
        <p role="status" aria-live="polite">${state.errorSummary}</p>
        <p role="status" aria-live="polite">${state.failureSummary}</p>
        <details class="reality-panel">
          <summary>Reality check — this exhibit</summary>
          <div class="reality-content">
            <div class="reality-row"><span class="reality-badge">✅ Real</span><span>Error sampling uses spec-accurate σ and bounds per parameter set<sup class="cite"><a href="#ref-4">[4]</a></sup>. The discrete Gaussian-like distribution is genuine.</span></div>
            <div class="reality-row"><span class="reality-badge">⚠️ Simplified</span><span>Toy decryption failure uses q=17 (vs q≥2<sup>15</sup>). Sampling uses floating-point weights, not constant-time CDF table lookup.</span></div>
            <div class="reality-row"><span class="reality-badge">🚫 Not guaranteed</span><span>Constant-time execution or side-channel resistance.</span></div>
          </div>
        </details>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Histogram (selected: ${params.label})</h3>
          <div class="histogram" role="img" aria-label="Error distribution histogram for ${params.label}, showing sampled counts per error value">
            ${state.errorHistogram
              .map(
                (bin) => `<div class="hist-row"><span>${bin.value}</span><div class="hist-track"><div class="hist-fill" style="--w:${
                  (bin.count / histMax) * 100
                }%;"></div></div><span>${bin.count}</span></div>`,
              )
              .join('')}
          </div>
        </div>
        <div>
          <h3>Error comparison table</h3>
          <table>
            <caption class="sr-only">Error distribution comparison by scheme</caption>
            <thead><tr><th scope="col">Scheme</th><th scope="col">Error type</th><th scope="col">σ</th><th scope="col">Max error</th></tr></thead>
            <tbody>
              <tr><td>FrodoKEM-640</td><td>Discrete, table-sampled</td><td>2.8</td><td>±12</td></tr>
              <tr><td>FrodoKEM-976</td><td>Discrete, table-sampled</td><td>2.3</td><td>±10</td></tr>
              <tr><td>ML-KEM-768</td><td>Centered binomial CBD(3)</td><td>1.22</td><td>±3</td></tr>
            </tbody>
          </table>
          <p>FrodoKEM-976 decryption failure target: &lt; 2<sup>-150</sup>.</p>
        </div>
      </article>

      ${state.failProbs.length > 0 ? `
      <article class="card">
        <h3>Failure probability vs error magnitude (toy q=17)</h3>
        <div class="fail-chart">
          ${state.failProbs.map((fp) => {
            const pct = (fp.rate * 100);
            const cls = fp.rate === 0 ? 'safe' : fp.rate < 0.15 ? 'risky' : 'broken';
            return `<div class="fail-row"><span>±${fp.maxErr}</span><div class="fail-track"><div class="fail-fill ${cls}" style="--w:${Math.max(pct, 1)}%;"></div></div><span>${(pct).toFixed(1)}%</span></div>`;
          }).join('')}
        </div>
        <p>Green = 0% failure, yellow = occasional, red = frequent. The cliff is sharp — small increases in error magnitude cause catastrophic failure rates.</p>
      </article>` : ''}

      <article class="card callout">
        <strong>Why this matters:</strong> Error distributions are the bridge between LWE proofs and practical implementations. FrodoKEM chooses conservative parameters even at performance cost.
      </article>

      ${renderTakeaway('errors')}
    </section>

    <section class="panel ${state.activeTab === 'landscape' ? 'visible' : ''}" id="panel-landscape" role="tabpanel" aria-labelledby="tab-landscape" ${state.activeTab !== 'landscape' ? 'hidden' : ''}>
      ${renderObjective('landscape')}
      <article class="card">
        <h2>FrodoKEM in the PQ KEM landscape <span class="badge badge-real">Published data</span></h2>
        <div class="table-wrap">
          <table>
            <caption class="sr-only">Post-quantum KEM landscape comparison</caption>
            <thead><tr><th scope="col">KEM</th><th scope="col">Basis</th><th scope="col">NIST status</th><th scope="col">Key size</th><th scope="col">Speed</th></tr></thead>
            <tbody>
              <tr><td>ML-KEM</td><td>Module-LWE</td><td>FIPS 203 (2024)</td><td>~1KB</td><td>Fast</td></tr>
              <tr><td>FrodoKEM</td><td>Plain LWE</td><td>Round 4 alternate</td><td>~15KB</td><td>Slower</td></tr>
              <tr><td>BIKE</td><td>Code-based</td><td>Round 4 alternate</td><td>~1.5KB</td><td>Slow</td></tr>
              <tr><td>HQC</td><td>Code-based</td><td>Round 4 alternate</td><td>~3KB</td><td>Slow</td></tr>
              <tr><td>Classic McEliece</td><td>Code-based</td><td>Round 4 alternate</td><td>~261KB</td><td>Slow</td></tr>
            </tbody>
          </table>
        </div>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Cross-demo links</h3>
          <ul>
            <li><a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener">ML-KEM demo</a></li>
            <li><a href="https://systemslibrarian.github.io/crypto-lab-bike-vault/" target="_blank" rel="noopener">BIKE demo</a></li>
            <li><a href="https://systemslibrarian.github.io/crypto-lab-hqc-vault/" target="_blank" rel="noopener">HQC demo</a></li>
            <li><a href="https://systemslibrarian.github.io/crypto-lab-mceliece-gate/" target="_blank" rel="noopener">Classic McEliece demo</a></li>
            <li><a href="https://systemslibrarian.github.io/crypto-compare/" target="_blank" rel="noopener">Crypto Compare dashboard</a></li>
          </ul>
        </div>
        <div>
          <button class="collapsible-toggle" aria-expanded="${state.openCollapsibles.has('belt-suspenders')}" data-collapse="belt-suspenders">Belt-and-suspenders recommendation</button>
          <div class="collapsible-body ${state.openCollapsibles.has('belt-suspenders') ? 'open' : ''}" id="belt-suspenders">
          <p>For most deployments, ML-KEM-768 is enough. For highest assurance, combine ML-KEM-768 + FrodoKEM-976.</p>
          <p>Hybrid secret derivation: <code>SS = KDF(SS_mlkem || SS_frodo)</code>. Security holds if either KEM remains secure.</p>
          <p>20-year horizon framing: FrodoKEM is explicit insurance against uncertain long-term structural risk.</p>
          <p>Deployment notes: FrodoKEM was originated at Microsoft Research and appears in high-assurance hybrid deployments such as Amazon s2n-tls options.</p>
          </div>
        </div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> FrodoKEM is not the default KEM. It is the conservative option for secrets where long-term risk tolerance is near zero.
      </article>

      ${renderTakeaway('landscape')}
    </section>

    <section class="panel ${state.activeTab === 'divide' ? 'visible' : ''}" id="panel-divide" role="tabpanel" aria-labelledby="tab-divide" ${state.activeTab !== 'divide' ? 'hidden' : ''}>
      ${renderObjective('divide')}

      <article class="card evidence-key">
        <h3>How to read this exhibit</h3>
        <p>This is the one exhibit where fact, decision, and interpretation mix. Each claim below is tagged so you can tell them apart:</p>
        <ul class="evidence-legend">
          <li><span class="ev ev-spec">Published spec</span> in a public, peer-reviewable document</li>
          <li><span class="ev ev-decision">Standards decision</span> an official standards-body action</li>
          <li><span class="ev ev-statement">Public statement</span> an attributed quote or announcement</li>
          <li><span class="ev ev-interp">Interpretation</span> strategic analysis, not a sourced fact</li>
          <li><span class="ev ev-unknown">Unknown</span> not yet publicly specified</li>
        </ul>
      </article>

      <article class="card">
        <h2>Two Philosophies, One Problem <span class="badge badge-real">Sourced analysis</span></h2>
        <div class="table-wrap">
          <table class="divide-table">
            <caption class="sr-only">Structured vs structureless lattice comparison</caption>
            <thead>
              <tr>
                <th scope="col"></th>
                <th scope="col">Structured Lattices (NIST path)</th>
                <th scope="col">Structureless Lattices (China path)</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>Math basis</td><td>Ring-LWE / Module-LWE</td><td>Plain LWE (no ring)</td></tr>
              <tr><td>Speed</td><td>Fast — NTT-optimized</td><td>Slower — matrix multiply</td></tr>
              <tr><td>Key sizes</td><td>Compact (~800 B – 1.5 KB)</td><td>Large (~10–20 KB)</td></tr>
              <tr><td>Security proof</td><td>Reduction gap exists</td><td>Cleaner worst-case reduction</td></tr>
              <tr class="divide-highlight"><td>Algebraic attack surface</td><td>Present</td><td>Absent</td></tr>
              <tr><td>Standards status</td><td>NIST FIPS 203/204 (2024)</td><td>China target: ~2028–2029</td></tr>
              <tr><td>Named algorithms</td><td>ML-KEM, ML-DSA, FALCON</td><td>S-Cloud+ (announced)</td></tr>
            </tbody>
          </table>
        </div>
        <p>Algebraic lattice schemes gain their speed from a mathematical shortcut: polynomial ring arithmetic, accelerated by the Number Theoretic Transform (NTT)<sup class="cite"><a href="#ref-6">[6]</a></sup>. That same structure is an extra attack surface — one that the underlying plain-LWE hardness proof does not cover. Whether that gap will ever be exploited is unknown. That uncertainty is exactly what drives the structureless approach.</p>
      </article>

      <article class="card">
        <h2>S-Cloud+ and the Structureless Bet</h2>
        <div class="caveat-box" role="note">
          <strong>⚠ No public specification.</strong> <span class="ev ev-unknown">Unknown</span> As of this writing, S-Cloud+ has <em>no published cryptographic specification</em> — parameter sets, key sizes, and security proofs are not public. Everything below about its design is inferred from public remarks, not a peer-reviewed document.
        </div>
        <blockquote>
          <span class="ev ev-statement">Public statement</span>
          "International standards based on algebraic lattices have some degree of security degradation. But structureless cryptographic algorithms basically do not have this problem."
          <footer>— Wang Xiaoyun, Tsinghua University, National People's Congress, Beijing, March 2026<sup class="cite"><a href="#ref-8">[8]</a></sup></footer>
        </blockquote>
        <p>China's leading structureless algorithm candidate is S-Cloud+, promoted as the domestic alternative to ML-KEM. <span class="ev ev-interp">Interpretation</span> Its stated design philosophy mirrors FrodoKEM: plain LWE over an integer matrix, no ring structure, no NTT. <span class="ev ev-unknown">Unknown</span> Its parameter sets, key sizes, and exact security proofs are not yet published. What is signalled is the commitment: trade performance for the most conservative possible security foundation.</p>
        <p><span class="ev ev-decision">Standards decision</span> In February 2025, China's Institute of Commercial Cryptography Standards (OSCCA) issued a global call for post-quantum algorithm proposals<sup class="cite"><a href="#ref-7">[7]</a></sup> — a direct parallel to NIST's 2016 competition, with a distinctly different technical direction baked in. Wang Xiaoyun projected a three-to-five year timeline to domestic standards, with finance and energy sectors first in line for migration.</p>
        <p>The motivation is not purely mathematical. Every major technological power wants cryptographic independence — the ability to deploy standards it controls, audits, and trusts. China's earlier development of SM2, SM3, and SM4 (classical cryptography standards) and their mandatory domestic use established this pattern. S-Cloud+ is its post-quantum continuation.</p>
      </article>

      <article class="card">
        <h2>Even NIST Hedged</h2>
        <p><span class="ev ev-decision">Standards decision</span> In March 2025, NIST selected <strong>HQC</strong> — a code-based algorithm using completely different mathematics (error-correcting codes, not lattices) — as a fourth backup standard<sup class="cite"><a href="#ref-5">[5]</a></sup>. Dustin Moody, NIST's PQC project lead, stated the rationale directly: having a fallback in case ML-KEM proves vulnerable.</p>
        <p><span class="ev ev-interp">Interpretation</span> This reads as the Western establishment quietly acknowledging what China has said loudly: the algebraic lattice bet might not be safe forever.</p>
        <ul>
          <li><strong>China's approach:</strong> Don't use algebraic lattices to begin with. Use plain LWE (S-Cloud+).</li>
          <li><strong>NIST's approach:</strong> Use algebraic lattices (ML-KEM) as the primary standard, but hold HQC in reserve in case of a breakthrough.</li>
        </ul>
        <p>Both strategies acknowledge the same risk. They differ in how much they trust the algebraic structure.</p>
      </article>

      <article class="card">
        <h2>FrodoKEM as the Bridge</h2>
        <p>FrodoKEM is not S-Cloud+. But they are philosophical siblings — both plain LWE, both structureless, both accepting the performance cost to gain the cleaner security proof. When China finalizes S-Cloud+ parameters and publishes its specification, the math you have explored in Exhibits 1–5 of this demo is the math that will underlie it. FrodoKEM is the working, publicly specified, NIST-evaluated embodiment of exactly the approach China has chosen as its strategic bet.</p>
        <div class="timeline">
          <div class="timeline-item"><span class="timeline-year">2016</span><span class="timeline-text">FrodoKEM published (Bos et al., Microsoft Research)</span></div>
          <div class="timeline-item"><span class="timeline-year">2022</span><span class="timeline-text">FrodoKEM eliminated from NIST Round 4 — performance concerns</span></div>
          <div class="timeline-item"><span class="timeline-year">2024</span><span class="timeline-text">NIST finalizes ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)</span></div>
          <div class="timeline-item"><span class="timeline-year">2025</span><span class="timeline-text">NIST selects HQC as backup standard (March)</span></div>
          <div class="timeline-item"><span class="timeline-year">2025</span><span class="timeline-text">China OSCCA issues global PQC algorithm call (February)</span></div>
          <div class="timeline-item"><span class="timeline-year">2026</span><span class="timeline-text">Wang Xiaoyun announces S-Cloud+ direction at NPC (March)</span></div>
          <div class="timeline-item"><span class="timeline-year">~2028</span><span class="timeline-text">China domestic PQC standards expected</span></div>
        </div>
      </article>

      <article class="card">
        <h2>Explore the Full Landscape</h2>
        <ul>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener"><strong>kyber-vault</strong></a> — ML-KEM structured lattice KEM (the NIST standard that S-Cloud+ is the alternative to)</li>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noopener"><strong>dilithium-seal</strong></a> — ML-DSA structured lattice signatures (FIPS 204)</li>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-bike-vault/" target="_blank" rel="noopener"><strong>bike-vault</strong></a> — BIKE code-based KEM (same mathematical family as HQC, NIST's hedge)</li>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-hqc-vault/" target="_blank" rel="noopener"><strong>hqc-vault</strong></a> — HQC code-based KEM (NIST's actual backup standard)</li>
        </ul>
      </article>

      ${renderTakeaway('divide')}
    </section>

    ${renderMisconceptions()}

    <section class="about-panel" aria-label="About this demo">
      <h2>About This Demo</h2>
      <div class="about-grid">
        <div class="about-col">
          <h3>✓ This demo is</h3>
          <ul>
            <li>A working FrodoKEM playground that runs real keygen, encapsulation, and decapsulation via liboqs (WebAssembly) for all three security levels (640, 976, 1344)</li>
            <li>A demonstration of the LWE problem, noise distributions, and decryption-failure mechanics using genuine modular arithmetic</li>
            <li>An interactive tool for comparing FrodoKEM and ML-KEM by key size, security level, and <em>measured</em> in-browser speed</li>
          </ul>
        </div>
        <div class="about-col">
          <h3>✗ This demo is not</h3>
          <ul>
            <li>A key-management system — keys and shared secrets are ephemeral, kept only in page memory, and never persisted, reused, or exchanged with a real peer</li>
            <li>A replacement for integrating liboqs or PQClean yourself in a real application</li>
            <li>A guarantee of constant-time execution or side-channel resistance in this in-browser context</li>
          </ul>
        </div>
      </div>
    </section>

    <section class="insight-panel">
      <h2>What This Demonstrates</h2>
      <p>Most explanations of FrodoKEM focus on its difference from ML-KEM: no ring structure. This demo shows the concrete cost of that conservatism — a 15,632-byte public key versus 1,184 bytes — and lets you explore why the error distribution is the real engineering bottleneck. The toy LWE exhibit makes visible how adding a single unit of noise to a solvable linear system makes it inconsistent, which is exactly the hardness guarantee that secures the full-scale scheme.</p>
    </section>

    <section class="references-section" id="references">
      <h2>Sources & References</h2>
      <div class="impl-note">
        <strong>Implementation note:</strong> Exhibits 2–4 run real FrodoKEM and ML-KEM-768 from <a href="https://github.com/open-quantum-safe/liboqs" target="_blank" rel="noopener">liboqs</a> compiled to WebAssembly (via the <code>@oqs/liboqs-js</code> package), using the eFrodoKEM-*-AES variants whose sizes match the tables above. Keygen, encapsulation, decapsulation, the tamper test, the timing benchmark, and the hybrid derivation are genuine cryptographic operations. The first-principles LWE solver (Exhibit 1) and error sampling (Exhibit 5) are deliberately toy-scale teaching models. To secure real data, integrate liboqs or PQClean directly rather than copying this UI.
      </div>
      <ol class="reference-list">
        <li id="ref-1">Regev, O. (2005). "On Lattices, Learning with Errors, Random Linear Codes, and Cryptography." <em>Proceedings of the 37th ACM Symposium on Theory of Computing (STOC)</em>, pp. 84–93. <a href="https://doi.org/10.1145/1060590.1060603" target="_blank" rel="noopener">doi:10.1145/1060590.1060603</a></li>
        <li id="ref-2">Bos, J. W., Costello, C., Ducas, L., Mironov, I., Naehrig, M., Nikolaenko, V., Raghunathan, A., Stebila, D. (2016). "Frodo: Take off the Ring! Practical, Quantum-Secure Key Exchange from LWE." <em>ACM CCS 2016</em>. <a href="https://doi.org/10.1145/2976749.2978425" target="_blank" rel="noopener">doi:10.1145/2976749.2978425</a></li>
        <li id="ref-3">NIST (2024). "Module-Lattice-Based Key-Encapsulation Mechanism Standard." <em>FIPS 203</em>. <a href="https://doi.org/10.6028/NIST.FIPS.203" target="_blank" rel="noopener">doi:10.6028/NIST.FIPS.203</a></li>
        <li id="ref-4">Naehrig, M. et al. (2017–2023). "FrodoKEM: Learning With Errors Key Encapsulation." NIST PQC Round 3 Submission &amp; Specification. <a href="https://frodokem.org/" target="_blank" rel="noopener">frodokem.org</a></li>
        <li id="ref-5">NIST (2025). "NIST Selects HQC as Fifth Algorithm for Post-Quantum Cryptography Standardization." Press Release, March 11, 2025. <a href="https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-cryptography" target="_blank" rel="noopener">nist.gov</a></li>
        <li id="ref-6">Lyubashevsky, V., Peikert, C., Regev, O. (2010). "On Ideal Lattices and Learning with Errors Over Rings." <em>EUROCRYPT 2010</em>, LNCS 6110, pp. 1–23. <a href="https://doi.org/10.1007/978-3-642-13190-5_1" target="_blank" rel="noopener">doi:10.1007/978-3-642-13190-5_1</a></li>
        <li id="ref-7">OSCCA / TC260 (2025). "Call for Post-Quantum Cryptographic Algorithm Proposals." China Cryptography Standardization Technical Committee, February 2025.</li>
        <li id="ref-8">Wang Xiaoyun statements on structureless lattice cryptography at the National People's Congress, Beijing, March 2026. Reported by Chinese state media. <em>Note: S-Cloud+ does not yet have a published cryptographic specification as of April 2026; claims about its design are based on public remarks, not a peer-reviewed paper.</em></li>
      </ol>
    </section>
  </main>
  `;

  appRoot.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      state.activeTab = button.dataset.tab as TabId;
      history.pushState(null, '', '#' + state.activeTab);
      render();
    });
  });

  // Arrow-key navigation for tab list (WCAG tablist pattern)
  const tabButtons = Array.from(appRoot.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
  tabButtons.forEach((btn, idx) => {
    btn.setAttribute('tabindex', btn.classList.contains('active') ? '0' : '-1');
    btn.addEventListener('keydown', (e: KeyboardEvent) => {
      let next = -1;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        next = (idx + 1) % tabButtons.length;
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        next = (idx - 1 + tabButtons.length) % tabButtons.length;
      } else if (e.key === 'Home') {
        next = 0;
      } else if (e.key === 'End') {
        next = tabButtons.length - 1;
      }
      if (next >= 0) {
        e.preventDefault();
        tabButtons[next].focus();
        tabButtons[next].click();
      }
    });
  });

  // Collapsible sections
  appRoot.querySelectorAll<HTMLButtonElement>('.collapsible-toggle').forEach((toggle) => {
    toggle.addEventListener('click', () => {
      const targetId = toggle.dataset.collapse;
      if (!targetId) return;
      const body = appRoot.querySelector(`#${targetId}`);
      if (!body) return;
      const isOpen = state.openCollapsibles.has(targetId);
      if (isOpen) {
        state.openCollapsibles.delete(targetId);
      } else {
        state.openCollapsibles.add(targetId);
      }
      body.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(!isOpen));
    });
  });

  // Prediction checkpoints: record the learner's guess, then reveal feedback.
  appRoot.querySelectorAll<HTMLButtonElement>('[data-checkpoint][data-choice]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.checkpoint;
      const choice = btn.dataset.choice;
      if (!id || !choice || state.predictions[id]) return;
      state.predictions[id] = choice;
      render();
    });
  });

  const randSecret = appRoot.querySelector<HTMLButtonElement>('#rand-secret');
  randSecret?.addEventListener('click', () => {
    state.lweSecret = [randomFromRange(0, 96), randomFromRange(0, 96), randomFromRange(0, 96)];
    state.lweOutcome = `Secret randomized to [${state.lweSecret.join(', ')}].`;
    state.lweSamples = [];
    render();
  });

  const genSamples = appRoot.querySelector<HTMLButtonElement>('#gen-samples');
  genSamples?.addEventListener('click', () => {
    const s0 = parseInt(appRoot.querySelector<HTMLInputElement>('#s0')?.value ?? '0', 10) || 0;
    const s1 = parseInt(appRoot.querySelector<HTMLInputElement>('#s1')?.value ?? '0', 10) || 0;
    const s2 = parseInt(appRoot.querySelector<HTMLInputElement>('#s2')?.value ?? '0', 10) || 0;
    state.lweSecret = [mod(s0, 97), mod(s1, 97), mod(s2, 97)];
    state.lweSamples = buildToyLweSamples(state.lweSecret, true, state.lweNoiseMag);
    state.lweCleanSamples = buildToyLweSamples(state.lweSecret, false);
    state.lweOutcome = 'Generated 5 noisy samples and 3 noiseless equations from the selected secret.';
    render();
  });

  const noiseSlider = appRoot.querySelector<HTMLInputElement>('#noise-mag');
  noiseSlider?.addEventListener('input', () => {
    state.lweNoiseMag = parseInt(noiseSlider.value, 10);
    // Update label and hint text without full re-render to keep slider focus
    const label = noiseSlider.closest('.noise-slider-wrap')?.querySelector('label');
    if (label) label.innerHTML = `Error magnitude: <strong>${state.lweNoiseMag}</strong>`;
    const hint = noiseSlider.closest('.noise-slider-wrap')?.querySelector('span:last-child');
    if (hint) hint.textContent = state.lweNoiseMag === 0 ? 'No noise' : state.lweNoiseMag <= 3 ? 'Small (solvable)' : state.lweNoiseMag <= 12 ? 'Medium (hard)' : 'Large (impossible)';
    if (state.lweSamples.length > 0) {
      state.lweSamples = buildToyLweSamples(state.lweSecret, true, state.lweNoiseMag);
      state.lweOutcome = `Regenerated samples with error magnitude ±${state.lweNoiseMag}.`;
      // Update just the samples table and outcome text
      const tbody = appRoot.querySelector('#panel-lwe table tbody');
      if (tbody) {
        tbody.innerHTML = state.lweSamples.map(
          (row, i) => `<tr><td>${i + 1}</td><td>[${row.a.join(', ')}]</td><td>${row.b}</td><td>${row.e}</td></tr>`
        ).join('');
      }
      const outcome = appRoot.querySelector('#panel-lwe [role="status"]');
      if (outcome) outcome.textContent = state.lweOutcome;
    }
  });

  const matrixAnimBtn = appRoot.querySelector<HTMLButtonElement>('#run-matrix-anim');
  matrixAnimBtn?.addEventListener('click', () => {
    runMatrixAnimation();
  });

  const solveClean = appRoot.querySelector<HTMLButtonElement>('#solve-clean');
  solveClean?.addEventListener('click', () => {
    if (state.lweCleanSamples.length < 3) {
      state.lweOutcome = 'Generate samples first.';
      render();
      return;
    }
    const solved = solve3x3Mod97(state.lweCleanSamples);
    state.lweOutcome = solved
      ? `Without noise, Gaussian elimination recovers s = [${solved.join(', ')}] exactly.`
      : 'Noiseless system was singular; generate new samples.';
    render();
  });

  const solveNoisy = appRoot.querySelector<HTMLButtonElement>('#solve-noisy');
  solveNoisy?.addEventListener('click', () => {
    if (state.lweSamples.length < 3) {
      state.lweOutcome = 'Generate noisy samples first.';
      render();
      return;
    }
    const candidate = solve3x3Mod97(state.lweSamples.slice(0, 3));
    if (!candidate) {
      state.lweOutcome = 'Noisy system was singular; regenerate samples.';
      render();
      return;
    }
    const residuals = state.lweSamples.map((row) => mod(vecDot(row.a, candidate, 97) - row.b, 97));
    const inconsistent = residuals.some((r) => r !== 0);
    state.lweOutcome = inconsistent
      ? `With noise, equations become inconsistent. Candidate s = [${candidate.join(', ')}], residuals = [${residuals.join(', ')}].`
      : `This sample happened to fit exactly. Try again; noise usually breaks exact solving.`;
    render();
  });

  const paramSelect = appRoot.querySelector<HTMLSelectElement>('#param-select');
  paramSelect?.addEventListener('change', () => {
    state.selectedParam = paramSelect.value as FrodoId;
    render();
  });

  const runKeygen = appRoot.querySelector<HTMLButtonElement>('#run-keygen');
  runKeygen?.addEventListener('click', async () => {
    if (state.keygenBusy) return;
    const p = FRODO[state.selectedParam];
    state.keygenBusy = true;
    state.keygenRatio = '';
    state.keygenPreview = '';
    state.keygenSkSize = 0;
    state.keygenMs = 0;
    render();
    try {
      // REAL: liboqs expands seedA via AES/SHAKE, samples S,E, computes B = A·S + E mod q.
      const kem = await getFrodoKem(p.id);
      await yieldToPaint();
      const start = performance.now();
      const { publicKey, secretKey } = kem.generateKeyPair();
      state.keygenMs = performance.now() - start;
      state.keygenPreview = hexPreview(publicKey, 64);
      state.keygenSkSize = secretKey.length;
      state.keygenRatio = `${p.label} public key (${publicKey.length.toLocaleString()} bytes) is ${(publicKey.length / 1184).toFixed(1)}× the size of an ML-KEM-768 public key.`;
    } catch {
      state.keygenRatio = 'Key generation failed — the FrodoKEM WASM module could not load in this browser.';
    } finally {
      state.keygenBusy = false;
      render();
    }
  });

  const kemGen = appRoot.querySelector<HTMLButtonElement>('#kem-gen');
  kemGen?.addEventListener('click', async () => {
    if (state.kemBusy) return;
    const p = FRODO[state.selectedParam];
    state.kemBusy = true;
    state.kemStatus = `Generating Alice's ${p.label} keypair… (first run downloads the WASM module)`;
    render();
    try {
      // REAL FrodoKEM key generation via liboqs.
      const kem = await getFrodoKem(p.id);
      await yieldToPaint();
      const { publicKey, secretKey } = kem.generateKeyPair();
      state.kemParamId = p.id;
      state.kemAlicePk = publicKey;
      state.kemAliceSk = secretKey;
      state.kemCiphertext = null;
      state.kemBobSecret = null;
      state.kemAliceSecret = null;
      state.kemEncapMs = 0;
      state.kemDecapMs = 0;
      state.kemPreTamperCt = null;
      state.kemStatus = `Alice's real ${p.label} keypair is ready (pk ${publicKey.length.toLocaleString()} B, sk ${secretKey.length.toLocaleString()} B). Bob can encapsulate now.`;
    } catch {
      state.kemStatus = 'Key generation failed — the FrodoKEM WASM module could not load in this browser.';
    } finally {
      state.kemBusy = false;
      render();
    }
  });

  const kemEncap = appRoot.querySelector<HTMLButtonElement>('#kem-encap');
  kemEncap?.addEventListener('click', async () => {
    if (state.kemBusy) return;
    if (!state.kemAlicePk || !state.kemParamId) {
      state.kemStatus = 'Generate Alice keypair first.';
      render();
      return;
    }
    const id = state.kemParamId;
    state.kemBusy = true;
    state.kemStatus = `Bob is encapsulating against Alice's ${FRODO[id].label} public key…`;
    render();
    try {
      // REAL encapsulation: sample S',E',E"; B' = A·S' + E'; V = B·S' + E";
      // encode a random μ; ciphertext = (c1, c2); shared secret = KDF(...).
      const kem = await getFrodoKem(id);
      await yieldToPaint();
      const start = performance.now();
      const { ciphertext, sharedSecret } = kem.encapsulate(state.kemAlicePk!);
      state.kemEncapMs = performance.now() - start;
      state.kemCiphertext = ciphertext;
      state.kemBobSecret = sharedSecret;
      state.kemAliceSecret = null;
      state.kemPreTamperCt = null;
      state.kemStatus = `Bob encapsulated with ${FRODO[id].label}: ciphertext ${ciphertext.length.toLocaleString()} B, shared secret ${sharedSecret.length} B. Now let Alice decapsulate.`;
    } catch {
      state.kemStatus = 'Encapsulation failed unexpectedly.';
    } finally {
      state.kemBusy = false;
      render();
    }
  });

  const kemDecap = appRoot.querySelector<HTMLButtonElement>('#kem-decap');
  kemDecap?.addEventListener('click', async () => {
    if (state.kemBusy) return;
    if (!state.kemAliceSk || !state.kemCiphertext || !state.kemParamId) {
      state.kemStatus = 'Encapsulate first.';
      render();
      return;
    }
    const id = state.kemParamId;
    state.kemBusy = true;
    state.kemStatus = `Alice is decapsulating with her ${FRODO[id].label} secret key…`;
    render();
    try {
      // REAL decapsulation: W = B'·S; recover μ; re-encapsulate to validate;
      // derive the shared secret (or, on a bad ciphertext, an implicit-reject secret).
      const kem = await getFrodoKem(id);
      await yieldToPaint();
      const start = performance.now();
      state.kemAliceSecret = kem.decapsulate(state.kemCiphertext!, state.kemAliceSk!);
      state.kemDecapMs = performance.now() - start;
      const tampered = state.kemPreTamperCt !== null;
      const match = state.kemBobSecret ? bytesEqual(state.kemAliceSecret, state.kemBobSecret) : false;
      state.kemStatus = match
        ? "Alice decapsulated and recovered the identical shared secret — the KEM round-trip succeeded."
        : tampered
          ? 'Alice decapsulated, but the secret does NOT match: FrodoKEM detected the tampered ciphertext and returned an implicit-rejection secret.'
          : 'Alice decapsulated, but the secrets do not match.';
    } catch {
      state.kemStatus = 'Decapsulation failed unexpectedly.';
    } finally {
      state.kemBusy = false;
      render();
    }
  });

  const kemTamper = appRoot.querySelector<HTMLButtonElement>('#kem-tamper');
  kemTamper?.addEventListener('click', () => {
    if (state.kemBusy) return;
    if (!state.kemCiphertext) {
      state.kemStatus = 'No ciphertext to tamper.';
      render();
      return;
    }
    if (!state.kemPreTamperCt) {
      state.kemPreTamperCt = new Uint8Array(state.kemCiphertext);
    }
    const idx = randomInt(state.kemCiphertext.length);
    state.kemCiphertext[idx] = state.kemCiphertext[idx] ^ 0x01;
    state.kemStatus = `Flipped one bit of the ciphertext at byte ${idx}. Decapsulate again — FrodoKEM's implicit rejection will yield a different secret.`;
    render();
  });

  const runCompare = appRoot.querySelector<HTMLButtonElement>('#run-compare');
  runCompare?.addEventListener('click', async () => {
    if (state.compareBusy) return;
    state.compareBusy = true;
    state.compareBench = 'Benchmarking real keygen / encaps / decaps in your browser…';
    render();
    try {
      // REAL benchmark of actual liboqs WASM ops on THIS device. We measure the
      // one-time WASM load separately, run warm-up iterations (discarded) so the
      // JIT has settled, then report median + min/max over the recorded samples.
      const warmup = 2;
      const samples = 11;
      const frodoLoad0 = performance.now();
      const frodo = await getFrodoKem('frodo976');
      const frodoLoadMs = performance.now() - frodoLoad0;
      const mlLoad0 = performance.now();
      const mlkem = await getMlKem768();
      const mlLoadMs = performance.now() - mlLoad0;
      await yieldToPaint();

      const bench = (kem: typeof frodo, loadMs: number): SchemeStats => {
        const { publicKey, secretKey } = kem.generateKeyPair();
        const { ciphertext } = kem.encapsulate(publicKey);
        return {
          keygen: statsMs(() => void kem.generateKeyPair(), samples, warmup),
          encaps: statsMs(() => void kem.encapsulate(publicKey), samples, warmup),
          decaps: statsMs(() => void kem.decapsulate(ciphertext, secretKey), samples, warmup),
          loadMs,
        };
      };

      const frodoStats = bench(frodo, frodoLoadMs);
      const mlkemStats = bench(mlkem, mlLoadMs);
      state.compareStats = { samples, warmup, frodo: frodoStats, mlkem: mlkemStats };
      const ratio = frodoStats.keygen.median / Math.max(mlkemStats.keygen.median, 0.0001);
      state.compareBench = `Measured on this device. FrodoKEM-976 keygen is ≈${ratio.toFixed(1)}× ML-KEM-768’s here — the ratio is the lesson; absolute numbers vary by machine and browser.`;
    } catch {
      state.compareBench = 'Benchmark failed — a WASM module could not load in this browser.';
    } finally {
      state.compareBusy = false;
      render();
    }
  });

  const runHybrid = appRoot.querySelector<HTMLButtonElement>('#run-hybrid');
  runHybrid?.addEventListener('click', async () => {
    if (state.hybridBusy) return;
    state.hybridBusy = true;
    state.hybridStatus = 'Running real ML-KEM-768 + FrodoKEM-976 encapsulations…';
    render();
    try {
      // REAL hybrid: two genuine KEM encapsulations, combined with a KDF.
      const mlkem = await getMlKem768();
      const frodo = await getFrodoKem('frodo976');
      await yieldToPaint();
      const mlAlice = mlkem.generateKeyPair();
      const frAlice = frodo.generateKeyPair();
      state.hybridMlkemSS = mlkem.encapsulate(mlAlice.publicKey).sharedSecret;
      state.hybridFrodoSS = frodo.encapsulate(frAlice.publicKey).sharedSecret;
      state.hybridCombinedSS = await sha256(concat(state.hybridMlkemSS, state.hybridFrodoSS));
      state.hybridStatus = `Hybrid secret derived from two real KEMs: SHA-256(${state.hybridMlkemSS.length}-byte ML-KEM secret ∥ ${state.hybridFrodoSS.length}-byte FrodoKEM secret) → 32 bytes. Security holds if either KEM survives.`;
    } catch {
      state.hybridStatus = 'Hybrid derivation failed — a WASM module could not load in this browser.';
    } finally {
      state.hybridBusy = false;
      render();
    }
  });

  const sampleErrors = appRoot.querySelector<HTMLButtonElement>('#sample-errors');
  sampleErrors?.addEventListener('click', () => {
    const p = FRODO[state.selectedParam];
    state.errorHistogram = generateHistogram(p);
    state.errorSummary = `Sampled 1000 errors for ${p.label}. Distribution is centered near 0 with thin tails.`;
    render();
  });

  const runFailure = appRoot.querySelector<HTMLButtonElement>('#run-failure');
  runFailure?.addEventListener('click', () => {
    state.failureSummary = runFailureDemo();
    render();
  });

  const runFailChart = appRoot.querySelector<HTMLButtonElement>('#run-fail-chart');
  runFailChart?.addEventListener('click', () => {
    state.failProbs = computeFailureProbabilities();
    render();
  });

  // Scroll active tab into view in the horizontal tab bar
  const activeTabBtn = appRoot.querySelector<HTMLButtonElement>('.tab.active');
  activeTabBtn?.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
}

window.addEventListener('popstate', () => {
  const t = tabFromHash();
  if (t && t !== state.activeTab) {
    state.activeTab = t;
    render();
  }
});

// Theme toggling is owned entirely by the shared Crypto Lab header
// (its #cl-theme-toggle button + inline script in index.html, persisting to the
// same `theme` localStorage key the page reads on first paint).

state.lweSamples = buildToyLweSamples(state.lweSecret, true, state.lweNoiseMag);
state.lweCleanSamples = buildToyLweSamples(state.lweSecret, false);
render();
