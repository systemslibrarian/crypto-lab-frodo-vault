// ============================================================================
// Frodo Vault — Educational FrodoKEM Demonstration
// ============================================================================
//
// This project is an EDUCATIONAL SIMULATION, not a production cryptographic
// implementation. It demonstrates FrodoKEM concepts, parameter sizes, and
// protocol flow for learning purposes.
//
// What is REAL:  Parameter sizes, LWE math, noise distributions, byte counts
// What is SIMULATED: Key bytes, ciphertext bytes, shared secret derivation
//
// FrodoKEM parameter sets sourced from math.ts are spec-accurate:
//   FrodoKEM-640  (n=640),  FrodoKEM-976  (n=976),  FrodoKEM-1344 (n=1344)
// Toy LWE (n=3, q=97) is intentionally small for first-principles pedagogy.
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

type TabId = 'lwe' | 'keygen' | 'kem' | 'compare' | 'errors' | 'landscape' | 'divide';
type Theme = 'dark' | 'light';

const TABS: TabId[] = ['lwe', 'keygen', 'kem', 'compare', 'errors', 'landscape', 'divide'];

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
  aliceSeed: null as Uint8Array | null,
  kemCiphertext: null as Uint8Array | null,
  kemBobSecret: null as Uint8Array | null,
  kemAliceSecret: null as Uint8Array | null,
  kemEncapMs: 0,
  kemDecapMs: 0,
  kemStatus: 'Generate Alice keypair to begin encapsulation.',
  kemPreTamperCt: null as Uint8Array | null,
  compareBench: '',
  compareRows: {
    frodo: { keygen: 0, encaps: 0, decaps: 0 },
    mlkem: { keygen: 0, encaps: 0, decaps: 0 },
  },
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
  hybridStatus: 'Run the hybrid demo to derive a combined shared secret.',
  openCollapsibles: new Set<string>(),
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

function randomBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digestInput = new Uint8Array(data.byteLength);
  digestInput.set(data);
  const digest = await crypto.subtle.digest('SHA-256', digestInput);
  return new Uint8Array(digest);
}

// ---------------------------------------------------------------------------
// SIMULATION WRAPPERS
// These functions model FrodoKEM protocol flow for educational purposes.
// They produce CORRECTLY-SIZED outputs but do NOT perform real FrodoKEM
// cryptographic operations (no SHAKE-128 expansion, no matrix algebra,
// no constant-time guarantees).
// ---------------------------------------------------------------------------

// Simulates FrodoKEM key generation.
// Real keygen: seed → SHAKE-128 expand A → sample S,E → B = A·S + E mod q
// Simulation: generates random bytes matching spec-accurate sizes.
function simulateKeyGeneration(p: FrodoParams): { pk: Uint8Array; sk: Uint8Array } {
  return {
    pk: randomBytes(p.publicKey),
    sk: randomBytes(p.privateKey),
  };
}

// Simulates FrodoKEM encapsulation.
// Real encaps: sample S',E',E" → B'=A·S'+E', V=B·S'+E" → encode μ → ct=(c1,c2), SS=KDF
// Simulation: generates random ciphertext bytes, derives SS via SHA-256.
async function simulateEncapsulation(
  p: FrodoParams,
  aliceSeed: Uint8Array,
): Promise<{ ct: Uint8Array; sharedSecret: Uint8Array }> {
  const ct = randomBytes(p.ciphertext);
  const sharedSecret = await sha256(concat(aliceSeed, ct));
  return { ct, sharedSecret };
}

// Simulates FrodoKEM decapsulation.
// Real decaps: W=B'·S → recover μ → re-encapsulate for validation → KDF
// Simulation: derives the same SS via SHA-256(seed || ct).
async function simulateDecapsulation(
  aliceSeed: Uint8Array,
  ct: Uint8Array,
): Promise<Uint8Array> {
  return sha256(concat(aliceSeed, ct));
}

function getTheme(): Theme {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function setTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
}

function themeMeta(theme: Theme): { icon: string; label: string } {
  return theme === 'dark'
    ? { icon: '☀', label: 'Switch to light mode' }
    : { icon: '🌙', label: 'Switch to dark mode' };
}

// Simulates relative computational weight between FrodoKEM and ML-KEM.
// This is NOT a benchmark. Real performance depends on platform, implementation,
// and optimization level. The ~10× ratio shown here reflects published literature
// (see FrodoKEM spec §7, liboqs benchmarks) but exact numbers will differ.
function simulateRelativeWeight(scale: number): number {
  const start = performance.now();
  let acc = 0;
  for (let i = 0; i < scale; i += 1) {
    acc = mod(acc + (i * 17 + 11) * (i * 19 + 7), 65536);
  }
  const delta = performance.now() - start;
  return delta + acc * 0;
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
      <p class="subhead">The conservative post-quantum KEM based on plain LWE. Bigger keys, simpler assumption.</p>
    </div>

    <div class="disclaimer-banner" role="note">
      <strong>Educational simulation.</strong> This project demonstrates FrodoKEM concepts and protocol flow for learning purposes. It does not implement production FrodoKEM cryptography. Do not use for securing real data. <a href="#references">Sources &amp; references \u2192</a>
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

    <section class="panel ${state.activeTab === 'lwe' ? 'visible' : ''}" id="panel-lwe" role="tabpanel" aria-labelledby="tab-lwe" ${state.activeTab !== 'lwe' ? 'hidden' : ''}>
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
    </section>

    <section class="panel ${state.activeTab === 'keygen' ? 'visible' : ''}" id="panel-keygen" role="tabpanel" aria-labelledby="tab-keygen" ${state.activeTab !== 'keygen' ? 'hidden' : ''}>
      <article class="card">
        <h2>FrodoKEM key generation <span class="badge badge-sim">Simulated flow</span></h2>
        <p>Conceptual flow: seed → expand A (SHAKE-128), sample S and E from noise distribution, compute B = A·S + E mod q, publish (seed<sub>A</sub>, B)<sup class="cite"><a href="#ref-4">[4]</a></sup>.</p>
        <p>For FrodoKEM-976, n=976 and n̄=8. A full 976×976 matrix of 16-bit values would be about 1.9MB, so only seed<sub>A</sub> is stored.</p>
        <div class="controls">
          <label for="param-select">Parameter set</label>
          <select id="param-select">
            <option value="frodo640" ${state.selectedParam === 'frodo640' ? 'selected' : ''}>FrodoKEM-640</option>
            <option value="frodo976" ${state.selectedParam === 'frodo976' ? 'selected' : ''}>FrodoKEM-976</option>
            <option value="frodo1344" ${state.selectedParam === 'frodo1344' ? 'selected' : ''}>FrodoKEM-1344</option>
          </select>
          <button id="run-keygen">Generate keypair (simulated)</button>
        </div>
        <details class="reality-panel">
          <summary>Reality check — this exhibit</summary>
          <div class="reality-content">
            <div class="reality-row"><span class="reality-badge">✅ Real</span><span>All parameter sizes (pk, sk, ct) match the FrodoKEM specification exactly<sup class="cite"><a href="#ref-4">[4]</a></sup>. The conceptual keygen flow described above is accurate.</span></div>
            <div class="reality-row"><span class="reality-badge">⚠️ Simulated</span><span>Generated key bytes are random data, not computed via SHAKE-128 matrix expansion + LWE sampling. No actual A·S + E computation occurs.</span></div>
            <div class="reality-row"><span class="reality-badge">🚫 Not guaranteed</span><span>Cryptographic key validity. These keys cannot be used for encryption.</span></div>
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
    </section>

    <section class="panel ${state.activeTab === 'kem' ? 'visible' : ''}" id="panel-kem" role="tabpanel" aria-labelledby="tab-kem" ${state.activeTab !== 'kem' ? 'hidden' : ''}>
      <article class="card">
        <h2>Encapsulation and decapsulation <span class="badge badge-sim">Simulated flow</span></h2>
        <p>Conceptual encapsulation: sample S′, E′, E″, compute B′ = A·S′ + E′ and V = B·S′ + E″, encode message, output ciphertext (B′, C), derive shared secret via KDF<sup class="cite"><a href="#ref-4">[4]</a></sup>.</p>
        <p>Conceptual decapsulation: compute W = B′·S, recover message, re-encapsulate for validation, derive same shared secret.</p>
        <div class="controls">
          <button id="kem-gen">Generate Alice keypair (simulated)</button>
          <button id="kem-encap">Bob encapsulates (simulated)</button>
          <button id="kem-decap">Alice decapsulates (simulated)</button>
          <button id="kem-tamper">Tamper with ciphertext</button>
        </div>
        <p role="status" aria-live="polite">${state.kemStatus}</p>
        <details class="reality-panel">
          <summary>Reality check — this exhibit</summary>
          <div class="reality-content">
            <div class="reality-row"><span class="reality-badge">✅ Real</span><span>Ciphertext and key sizes match the FrodoKEM spec<sup class="cite"><a href="#ref-4">[4]</a></sup>. The protocol flow (keygen → encap → decap → shared secret) is structurally accurate. Tamper detection demonstrates KEM integrity properties.</span></div>
            <div class="reality-row"><span class="reality-badge">⚠️ Simulated</span><span>Ciphertext is random bytes, not LWE-encrypted data. Shared secret is derived via SHA-256(seed ∥ ct), not the FrodoKEM KDF. No matrix operations occur.</span></div>
            <div class="reality-row"><span class="reality-badge">🚫 Not guaranteed</span><span>IND-CCA2 security, resistance to chosen-ciphertext attacks, or real key exchange.</span></div>
          </div>
        </details>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Ciphertext and secret</h3>
          <p>Ciphertext preview: <code>${state.kemCiphertext ? hexPreview(state.kemCiphertext, 64) : '--'}</code></p>
          <p>Bob shared secret (32 bytes): <code>${state.kemBobSecret ? formatHex(state.kemBobSecret) : '--'}</code></p>
          <p>Alice shared secret (32 bytes): <code>${state.kemAliceSecret ? formatHex(state.kemAliceSecret) : '--'}</code></p>
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
    </section>

    <section class="panel ${state.activeTab === 'compare' ? 'visible' : ''}" id="panel-compare" role="tabpanel" aria-labelledby="tab-compare" ${state.activeTab !== 'compare' ? 'hidden' : ''}>
      <article class="card">
        <h2>FrodoKEM vs ML-KEM: conservative choice <span class="badge badge-sim">Simulated timing</span></h2>
        <p>Size and security data below are from published specifications<sup class="cite"><a href="#ref-3">[3]</a></sup><sup class="cite"><a href="#ref-4">[4]</a></sup>. Timing values are relative computational weight simulations — they illustrate the approximate ratio, not measured benchmarks.</p>
        <button id="run-compare">Run relative weight simulation</button>
        <p role="status" aria-live="polite">${state.compareBench}</p>
        <details class="reality-panel">
          <summary>Reality check — this exhibit</summary>
          <div class="reality-content">
            <div class="reality-row"><span class="reality-badge">✅ Real</span><span>Key sizes, ciphertext sizes, security levels, and NIST status are from published specifications<sup class="cite"><a href="#ref-3">[3]</a></sup><sup class="cite"><a href="#ref-4">[4]</a></sup>.</span></div>
            <div class="reality-row"><span class="reality-badge">⚠️ Simulated</span><span>Timing values are synthetic loop-based weights scaled to approximate the ~10× ratio reported in published benchmarks (liboqs, FrodoKEM spec §7). Actual performance varies by platform.</span></div>
            <div class="reality-row"><span class="reality-badge">🚫 Not guaranteed</span><span>Reproducible benchmark numbers. For real measurements, see liboqs or PQClean benchmarks.</span></div>
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
            <tr><td>Key generation <span class="sim-notice">⚠️ simulated weight</span></td><td>${state.compareRows.frodo.keygen.toFixed(3)} ms</td><td>${state.compareRows.mlkem.keygen.toFixed(3)} ms</td></tr>
            <tr><td>Encapsulation <span class="sim-notice">⚠️ simulated weight</span></td><td>${state.compareRows.frodo.encaps.toFixed(3)} ms</td><td>${state.compareRows.mlkem.encaps.toFixed(3)} ms</td></tr>
            <tr><td>Decapsulation <span class="sim-notice">⚠️ simulated weight</span></td><td>${state.compareRows.frodo.decaps.toFixed(3)} ms</td><td>${state.compareRows.mlkem.decaps.toFixed(3)} ms</td></tr>
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
        <h3>Hybrid KEM walkthrough</h3>
        <p>Combine ML-KEM-768 + FrodoKEM-976 shared secrets into one hybrid secret. Security holds if <em>either</em> KEM remains secure.</p>
        <button id="run-hybrid">Run hybrid KEM derivation</button>
        <p role="status" aria-live="polite">${state.hybridStatus}</p>
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
    </section>

    <section class="panel ${state.activeTab === 'errors' ? 'visible' : ''}" id="panel-errors" role="tabpanel" aria-labelledby="tab-errors" ${state.activeTab !== 'errors' ? 'hidden' : ''}>
      <article class="card">
        <h2>Error distribution: where security lives <span class="badge badge-real">Real sampling</span></h2>
        <p>FrodoKEM uses discrete table-sampled errors approximating Gaussian behavior<sup class="cite"><a href="#ref-4">[4]</a></sup>. Errors must be random enough for security and small enough for correctness.</p>
        <div class="controls">
          <button id="sample-errors">Sample 1000 errors</button>
          <button id="run-failure">Run toy decryption failure</button>
          <button id="run-fail-chart">Failure probability chart</button>
        </div>
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
    </section>

    <section class="panel ${state.activeTab === 'landscape' ? 'visible' : ''}" id="panel-landscape" role="tabpanel" aria-labelledby="tab-landscape" ${state.activeTab !== 'landscape' ? 'hidden' : ''}>
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
    </section>

    <section class="panel ${state.activeTab === 'divide' ? 'visible' : ''}" id="panel-divide" role="tabpanel" aria-labelledby="tab-divide" ${state.activeTab !== 'divide' ? 'hidden' : ''}>

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
        <blockquote>
          "International standards based on algebraic lattices have some degree of security degradation. But structureless cryptographic algorithms basically do not have this problem."
          <footer>— Wang Xiaoyun, Tsinghua University, National People's Congress, Beijing, March 2026<sup class="cite"><a href="#ref-8">[8]</a></sup></footer>
        </blockquote>
        <p>China's leading structureless algorithm candidate is S-Cloud+, developed by Chinese cryptographers and actively promoted as the domestic alternative to ML-KEM. Its design philosophy is the same as FrodoKEM: plain LWE over an integer matrix, no ring structure, no NTT. As of April 2026, S-Cloud+ does not have a public cryptographic specification — its parameter sets, key sizes, and exact security proofs are not yet published. What is known is its philosophical commitment: trade performance for the most conservative possible security foundation.</p>
        <p>In February 2025, China's Institute of Commercial Cryptography Standards (OSCCA) issued a global call for post-quantum algorithm proposals<sup class="cite"><a href="#ref-7">[7]</a></sup> — a direct parallel to NIST's 2016 competition, with a distinctly different technical direction baked in. Wang Xiaoyun projected a three-to-five year timeline to domestic standards, with finance and energy sectors first in line for migration.</p>
        <p>The motivation is not purely mathematical. Every major technological power wants cryptographic independence — the ability to deploy standards it controls, audits, and trusts. China's earlier development of SM2, SM3, and SM4 (classical cryptography standards) and their mandatory domestic use established this pattern. S-Cloud+ is its post-quantum continuation.</p>
      </article>

      <article class="card">
        <h2>Even NIST Hedged</h2>
        <p>In March 2025, NIST selected <strong>HQC</strong> — a code-based algorithm using completely different mathematics (error-correcting codes, not lattices) — as a fourth backup standard<sup class="cite"><a href="#ref-5">[5]</a></sup>. Dustin Moody, NIST's PQC project lead, stated the rationale directly: having a fallback in case ML-KEM proves vulnerable.</p>
        <p>This is the Western establishment quietly acknowledging what China has said loudly: the algebraic lattice bet might not be safe forever.</p>
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

    </section>

    <section class="about-panel" aria-label="About this demo">
      <h2>About This Demo</h2>
      <div class="about-grid">
        <div class="about-col">
          <h3>✓ This demo is</h3>
          <ul>
            <li>An educational simulation of FrodoKEM key encapsulation with spec-accurate parameter sizes for all three security levels (640, 976, 1344)</li>
            <li>A working demonstration of the LWE problem, noise distributions, and decryption failure mechanics using genuine modular arithmetic</li>
            <li>An interactive tool for comparing FrodoKEM and ML-KEM key sizes, security levels, and computational trade-offs</li>
          </ul>
        </div>
        <div class="about-col">
          <h3>✗ This demo is not</h3>
          <ul>
            <li>A production FrodoKEM implementation — key bytes and ciphertexts are randomly generated, not computed via SHAKE-128 matrix expansion</li>
            <li>A substitute for vetted cryptographic libraries such as liboqs or PQClean</li>
            <li>A guarantee of constant-time execution, side-channel resistance, or real key exchange capability</li>
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
        <strong>Implementation note:</strong> This project does not implement real FrodoKEM cryptography. Key bytes, ciphertext bytes, and shared secrets shown in Exhibits 2–4 are randomly generated at spec-accurate sizes. The LWE math (Exhibit 1) and error sampling (Exhibit 5) are genuine computations. A real implementation would require a vetted library such as liboqs or PQClean.
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
  runKeygen?.addEventListener('click', () => {
    // SIMULATION: generates random bytes at spec-accurate sizes.
    // Real keygen would expand seed via SHAKE-128 and compute A·S + E.
    const p = FRODO[state.selectedParam];
    const start = performance.now();
    const { pk, sk } = simulateKeyGeneration(p);
    state.keygenMs = performance.now() - start;
    state.keygenPreview = hexPreview(pk, 64);
    state.keygenSkSize = sk.length;
    state.keygenRatio = `${p.label} public key (${p.publicKey} bytes) is ${(p.publicKey / 1184).toFixed(1)}x ML-KEM-768.`;
    render();
  });

  const kemGen = appRoot.querySelector<HTMLButtonElement>('#kem-gen');
  kemGen?.addEventListener('click', () => {
    // SIMULATION: generates a random seed to represent Alice's keypair.
    // Real keygen would produce structured pk/sk via LWE.
    state.aliceSeed = randomBytes(32);
    state.kemCiphertext = null;
    state.kemBobSecret = null;
    state.kemAliceSecret = null;
    state.kemEncapMs = 0;
    state.kemDecapMs = 0;
    state.kemPreTamperCt = null;
    state.kemStatus = 'Alice keypair generated (simulated). Bob can encapsulate now.';
    render();
  });

  const kemEncap = appRoot.querySelector<HTMLButtonElement>('#kem-encap');
  kemEncap?.addEventListener('click', async () => {
    if (!state.aliceSeed) {
      state.kemStatus = 'Generate Alice keypair first.';
      render();
      return;
    }
    try {
      // SIMULATION: generates random ciphertext bytes at spec-accurate size
      // and derives shared secret via SHA-256. Real encaps would compute
      // B' = A·S' + E' and V = B·S' + E", then encode μ.
      const p = FRODO[state.selectedParam];
      const start = performance.now();
      const { ct, sharedSecret } = await simulateEncapsulation(p, state.aliceSeed!);
      state.kemEncapMs = performance.now() - start;
      state.kemCiphertext = ct;
      state.kemBobSecret = sharedSecret;
      state.kemAliceSecret = null;
      state.kemPreTamperCt = null;
      state.kemStatus = `Bob encapsulated (simulated) using ${p.label}. Ciphertext size = ${p.ciphertext} bytes.`;
    } catch {
      state.kemStatus = 'Encapsulation failed — crypto.subtle may be unavailable (requires HTTPS).';
    }
    render();
  });

  const kemDecap = appRoot.querySelector<HTMLButtonElement>('#kem-decap');
  kemDecap?.addEventListener('click', async () => {
    if (!state.aliceSeed || !state.kemCiphertext) {
      state.kemStatus = 'Encapsulate first.';
      render();
      return;
    }
    try {
      // SIMULATION: derives shared secret via SHA-256(seed || ct).
      // Real decaps would compute W = B'·S, recover message, re-encapsulate.
      const start = performance.now();
      state.kemAliceSecret = await simulateDecapsulation(state.aliceSeed!, state.kemCiphertext!);
      state.kemDecapMs = performance.now() - start;
      state.kemStatus = 'Alice decapsulated (simulated) and derived a shared secret.';
    } catch {
      state.kemStatus = 'Decapsulation failed — crypto.subtle may be unavailable (requires HTTPS).';
    }
    render();
  });

  const kemTamper = appRoot.querySelector<HTMLButtonElement>('#kem-tamper');
  kemTamper?.addEventListener('click', () => {
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
    state.kemStatus = `Tampered ciphertext byte at index ${idx}. Next decapsulation should mismatch.`;
    render();
  });

  const runCompare = appRoot.querySelector<HTMLButtonElement>('#run-compare');
  runCompare?.addEventListener('click', () => {
    // SIMULATION: loop-based computational weight, not real crypto benchmarks.
    // The ~10× ratio reflects published FrodoKEM vs ML-KEM performance data.
    state.compareRows.frodo.keygen = simulateRelativeWeight(260000);
    state.compareRows.frodo.encaps = simulateRelativeWeight(220000);
    state.compareRows.frodo.decaps = simulateRelativeWeight(230000);

    state.compareRows.mlkem.keygen = simulateRelativeWeight(22000);
    state.compareRows.mlkem.encaps = simulateRelativeWeight(18000);
    state.compareRows.mlkem.decaps = simulateRelativeWeight(19000);

    state.compareBench = 'Relative weight simulation complete. Values illustrate approximate ratio, not measured performance.';
    render();
  });

  const runHybrid = appRoot.querySelector<HTMLButtonElement>('#run-hybrid');
  runHybrid?.addEventListener('click', async () => {
    try {
      state.hybridMlkemSS = randomBytes(32);
      state.hybridFrodoSS = randomBytes(24);
      state.hybridCombinedSS = await sha256(concat(state.hybridMlkemSS, state.hybridFrodoSS));
      state.hybridStatus = 'Hybrid derivation complete. Combined secret is 32 bytes via SHA-256.';
    } catch {
      state.hybridStatus = 'Hybrid derivation failed — crypto.subtle may be unavailable (requires HTTPS).';
    }
    render();
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

// CL header theme toggle
const clToggle = document.querySelector<HTMLButtonElement>('#themeToggle');
if (clToggle) {
  const syncToggle = () => {
    const m = themeMeta(getTheme());
    clToggle.textContent = m.icon;
    clToggle.setAttribute('aria-label', m.label);
  };
  syncToggle();
  clToggle.addEventListener('click', () => {
    setTheme(getTheme() === 'dark' ? 'light' : 'dark');
    syncToggle();
  });
}

state.lweSamples = buildToyLweSamples(state.lweSecret, true, state.lweNoiseMag);
state.lweCleanSamples = buildToyLweSamples(state.lweSecret, false);
render();
