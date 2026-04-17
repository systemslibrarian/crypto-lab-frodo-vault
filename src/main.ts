import './style.css';

type TabId = 'lwe' | 'keygen' | 'kem' | 'compare' | 'errors' | 'landscape' | 'divide';
type Theme = 'dark' | 'light';
type FrodoId = 'frodo640' | 'frodo976' | 'frodo1344';

type LweSample = {
  a: [number, number, number];
  b: number;
  e: number;
};

type FrodoParams = {
  id: FrodoId;
  label: string;
  n: number;
  q: number;
  classicalBits: number;
  pqBits: number;
  publicKey: number;
  privateKey: number;
  ciphertext: number;
  sigma: number;
  maxError: number;
};

const FRODO: Record<FrodoId, FrodoParams> = {
  frodo640: {
    id: 'frodo640',
    label: 'FrodoKEM-640',
    n: 640,
    q: 2 ** 15,
    classicalBits: 128,
    pqBits: 103,
    publicKey: 9616,
    privateKey: 19888,
    ciphertext: 9720,
    sigma: 2.8,
    maxError: 12,
  },
  frodo976: {
    id: 'frodo976',
    label: 'FrodoKEM-976',
    n: 976,
    q: 2 ** 16,
    classicalBits: 192,
    pqBits: 150,
    publicKey: 15632,
    privateKey: 31296,
    ciphertext: 15744,
    sigma: 2.3,
    maxError: 10,
  },
  frodo1344: {
    id: 'frodo1344',
    label: 'FrodoKEM-1344',
    n: 1344,
    q: 2 ** 16,
    classicalBits: 256,
    pqBits: 207,
    publicKey: 21520,
    privateKey: 43088,
    ciphertext: 21632,
    sigma: 1.4,
    maxError: 6,
  },
};

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('App root not found');
const appRoot = app;

const state = {
  activeTab: 'lwe' as TabId,
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
  compareBench: '',
  compareRows: {
    frodo: { keygen: 0, encaps: 0, decaps: 0 },
    mlkem: { keygen: 0, encaps: 0, decaps: 0 },
  },
  errorHistogram: [] as Array<{ value: number; count: number }>,
  errorSummary: 'Sample 1000 errors to visualize FrodoKEM-style discrete distribution.',
  failureSummary: 'Run the toy decryption-failure demo (n=4, q=17) with oversized errors.',
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

function mod(a: number, q: number): number {
  const v = a % q;
  return v < 0 ? v + q : v;
}

function modInv(a: number, q: number): number {
  let t = 0;
  let newT = 1;
  let r = q;
  let newR = mod(a, q);
  while (newR !== 0) {
    const quotient = Math.floor(r / newR);
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }
  if (r !== 1) throw new Error('No modular inverse');
  return mod(t, q);
}

function solve3x3Mod97(samples: LweSample[]): [number, number, number] | null {
  const q = 97;
  const m = samples.slice(0, 3).map((row) => [...row.a, row.b]);

  for (let col = 0; col < 3; col += 1) {
    let pivot = col;
    while (pivot < 3 && m[pivot][col] === 0) {
      pivot += 1;
    }
    if (pivot === 3) return null;
    if (pivot !== col) {
      [m[col], m[pivot]] = [m[pivot], m[col]];
    }

    const inv = modInv(m[col][col], q);
    for (let k = col; k < 4; k += 1) {
      m[col][k] = mod(m[col][k] * inv, q);
    }

    for (let r = 0; r < 3; r += 1) {
      if (r === col) continue;
      const factor = m[r][col];
      for (let k = col; k < 4; k += 1) {
        m[r][k] = mod(m[r][k] - factor * m[col][k], q);
      }
    }
  }

  return [m[0][3], m[1][3], m[2][3]];
}

function vecDot(a: [number, number, number], b: [number, number, number], q: number): number {
  return mod(a[0] * b[0] + a[1] * b[1] + a[2] * b[2], q);
}

function buildToyLweSamples(secret: [number, number, number], includeNoise: boolean): LweSample[] {
  const q = 97;
  const count = includeNoise ? 5 : 3;
  const samples: LweSample[] = [];
  while (samples.length < count) {
    const a: [number, number, number] = [randomFromRange(0, q - 1), randomFromRange(0, q - 1), randomFromRange(0, q - 1)];
    const e = includeNoise ? [-1, 0, 1][randomInt(3)] : 0;
    const b = mod(vecDot(a, secret, q) + e, q);
    samples.push({ a, b, e });
  }
  return samples;
}

function randomBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

function hexPreview(bytes: Uint8Array, shown = 64): string {
  const fullHex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${fullHex.slice(0, shown * 2)}... [${bytes.length - shown} more bytes]`;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digestInput = new Uint8Array(data.byteLength);
  digestInput.set(data);
  const digest = await crypto.subtle.digest('SHA-256', digestInput);
  return new Uint8Array(digest);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
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
    ? { icon: '🌙', label: 'Switch to light mode' }
    : { icon: '☀️', label: 'Switch to dark mode' };
}

function estimateOperationMs(scale: number): number {
  const start = performance.now();
  let acc = 0;
  for (let i = 0; i < scale; i += 1) {
    acc = mod(acc + (i * 17 + 11) * (i * 19 + 7), 65536);
  }
  const delta = performance.now() - start;
  return delta + acc * 0;
}

function normalPdfLike(x: number, sigma: number): number {
  return Math.exp(-(x * x) / (2 * sigma * sigma));
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

function formatHex(bytes: Uint8Array | null): string {
  if (!bytes) return '--';
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function render(): void {
  const theme = getTheme();
  const toggle = themeMeta(theme);
  const params = FRODO[state.selectedParam];
  const histMax = Math.max(1, ...state.errorHistogram.map((h) => h.count));
  const kemMatch =
    state.kemAliceSecret && state.kemBobSecret
      ? formatHex(state.kemAliceSecret) === formatHex(state.kemBobSecret)
      : false;

  appRoot.innerHTML = `
  <main id="main-content" class="shell">
    <header class="hero-header">
      <button id="theme-toggle" class="theme-toggle" type="button" aria-label="${toggle.label}">${toggle.icon}</button>
      <p class="eyebrow">crypto-lab demo</p>
      <h1>Frodo Vault: FrodoKEM without ring structure</h1>
      <p class="subhead">The conservative post-quantum KEM based on plain LWE. Bigger keys, simpler assumption.</p>
    </header>

    <nav class="tabs" role="tablist" aria-label="FrodoKEM exhibits">
      <button class="tab ${state.activeTab === 'lwe' ? 'active' : ''}" data-tab="lwe" role="tab" id="tab-lwe" aria-selected="${state.activeTab === 'lwe'}" aria-controls="panel-lwe">1. LWE Problem</button>
      <button class="tab ${state.activeTab === 'keygen' ? 'active' : ''}" data-tab="keygen" role="tab" id="tab-keygen" aria-selected="${state.activeTab === 'keygen'}" aria-controls="panel-keygen">2. Key Generation</button>
      <button class="tab ${state.activeTab === 'kem' ? 'active' : ''}" data-tab="kem" role="tab" id="tab-kem" aria-selected="${state.activeTab === 'kem'}" aria-controls="panel-kem">3. Encap / Decap</button>
      <button class="tab ${state.activeTab === 'compare' ? 'active' : ''}" data-tab="compare" role="tab" id="tab-compare" aria-selected="${state.activeTab === 'compare'}" aria-controls="panel-compare">4. Frodo vs ML-KEM</button>
      <button class="tab ${state.activeTab === 'errors' ? 'active' : ''}" data-tab="errors" role="tab" id="tab-errors" aria-selected="${state.activeTab === 'errors'}" aria-controls="panel-errors">5. Error Distribution</button>
      <button class="tab ${state.activeTab === 'landscape' ? 'active' : ''}" data-tab="landscape" role="tab" id="tab-landscape" aria-selected="${state.activeTab === 'landscape'}" aria-controls="panel-landscape">6. PQ Landscape</button>
      <button class="tab ${state.activeTab === 'divide' ? 'active' : ''}" data-tab="divide" role="tab" id="tab-divide" aria-selected="${state.activeTab === 'divide'}" aria-controls="panel-divide">7. The Global Divide</button>
    </nav>

    <section class="panel ${state.activeTab === 'lwe' ? 'visible' : ''}" id="panel-lwe" role="tabpanel" aria-labelledby="tab-lwe" ${state.activeTab !== 'lwe' ? 'hidden' : ''}>
      <article class="card">
        <h2>Learning With Errors (LWE) from first principles</h2>
        <p>LWE was introduced by Regev (2005). Given noisy linear equations over Z<sub>q</sub>, recover secret vector s.</p>
        <p>Formal sample: pick random a ∈ Z<sub>q</sub><sup>n</sup>, compute b = &lt;a, s&gt; + e mod q with small error e. Given many (a,b), recover s.</p>
        <p>Without noise this is linear algebra; with noise, equations become inconsistent and decoding is hard.</p>
        <blockquote>Educational LWE — toy parameters, not production. Toy interactive demo uses n=3, q=97, and e ∈ {-1, 0, 1}.</blockquote>
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
          <p role="status" aria-live="polite">${state.lweOutcome}</p>
        </div>
        <div>
          <h3>Ring-LWE vs plain LWE</h3>
          <ul>
            <li>Plain LWE (FrodoKEM): A is a random n×n matrix, no ring structure.</li>
            <li>Ring/Module-LWE (ML-KEM): structured polynomial algebra gives faster and smaller operations.</li>
            <li>FrodoKEM design choice: keep only the plain LWE assumption.</li>
          </ul>
          <p>Historical context: Regev (2005), Ring-LWE by Lyubashevsky-Peikert-Regev (2010), FrodoKEM (2016) "Take off the ring".</p>
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
    </section>

    <section class="panel ${state.activeTab === 'keygen' ? 'visible' : ''}" id="panel-keygen" role="tabpanel" aria-labelledby="tab-keygen" ${state.activeTab !== 'keygen' ? 'hidden' : ''}>
      <article class="card">
        <h2>FrodoKEM key generation</h2>
        <p>Conceptual flow: seed → expand A (SHAKE-128), sample S and E from noise distribution, compute B = A·S + E mod q, publish (seed<sub>A</sub>, B).</p>
        <p>For FrodoKEM-976, n=976 and n̄=8. A full 976×976 matrix of 16-bit values would be about 1.9MB, so only seed<sub>A</sub> is stored.</p>
        <div class="controls">
          <label for="param-select">Parameter set</label>
          <select id="param-select">
            <option value="frodo640" ${state.selectedParam === 'frodo640' ? 'selected' : ''}>FrodoKEM-640</option>
            <option value="frodo976" ${state.selectedParam === 'frodo976' ? 'selected' : ''}>FrodoKEM-976</option>
            <option value="frodo1344" ${state.selectedParam === 'frodo1344' ? 'selected' : ''}>FrodoKEM-1344</option>
          </select>
          <button id="run-keygen">Generate keypair</button>
        </div>
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
              <div class="bar-track"><div class="bar-fill" style="--w: 8%;"></div></div>
            </div>
            <div class="bar-line">
              <strong>FrodoKEM-976: 15,632 bytes</strong>
              <div class="bar-track"><div class="bar-fill" style="--w: 100%;"></div></div>
            </div>
          </div>
          <p>Ratio: FrodoKEM-976 public key is about 13.2× larger than ML-KEM-768.</p>
        </div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> Large keys are the price of avoiding ring/module structure. For high-value long-term secrets, this tradeoff can be acceptable.
      </article>
    </section>

    <section class="panel ${state.activeTab === 'kem' ? 'visible' : ''}" id="panel-kem" role="tabpanel" aria-labelledby="tab-kem" ${state.activeTab !== 'kem' ? 'hidden' : ''}>
      <article class="card">
        <h2>Encapsulation and decapsulation</h2>
        <p>Conceptual encapsulation: sample S′, E′, E″, compute B′ = A·S′ + E′ and V = B·S′ + E″, encode message, output ciphertext (B′, C), derive shared secret via KDF.</p>
        <p>Conceptual decapsulation: compute W = B′·S, recover message, re-encapsulate for validation, derive same shared secret.</p>
        <div class="controls">
          <button id="kem-gen">Generate Alice keypair</button>
          <button id="kem-encap">Bob encapsulates</button>
          <button id="kem-decap">Alice decapsulates</button>
          <button id="kem-tamper">Tamper with ciphertext</button>
        </div>
        <p role="status" aria-live="polite">${state.kemStatus}</p>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Ciphertext and secret</h3>
          <p>Ciphertext preview: <code>${state.kemCiphertext ? hexPreview(state.kemCiphertext, 64) : '--'}</code></p>
          <p>Bob shared secret (32 bytes): <code>${state.kemBobSecret ? formatHex(state.kemBobSecret) : '--'}</code></p>
          <p>Alice shared secret (32 bytes): <code>${state.kemAliceSecret ? formatHex(state.kemAliceSecret) : '--'}</code></p>
          <p>Encapsulation time: ${state.kemEncapMs ? `${state.kemEncapMs.toFixed(3)} ms` : '--'}</p>
          <p>Decapsulation time: ${state.kemDecapMs ? `${state.kemDecapMs.toFixed(3)} ms` : '--'}</p>
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
        <h2>FrodoKEM vs ML-KEM: conservative choice</h2>
        <p>Run a side-by-side operation simulation to compare practical timing shape with published size and security properties.</p>
        <button id="run-compare">Run side-by-side operation</button>
        <p role="status" aria-live="polite">${state.compareBench}</p>
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
            <tr><td>Key generation</td><td>${state.compareRows.frodo.keygen.toFixed(3)} ms</td><td>${state.compareRows.mlkem.keygen.toFixed(3)} ms</td></tr>
            <tr><td>Encapsulation</td><td>${state.compareRows.frodo.encaps.toFixed(3)} ms</td><td>${state.compareRows.mlkem.encaps.toFixed(3)} ms</td></tr>
            <tr><td>Decapsulation</td><td>${state.compareRows.frodo.decaps.toFixed(3)} ms</td><td>${state.compareRows.mlkem.decaps.toFixed(3)} ms</td></tr>
            <tr><td>NIST status</td><td>Round 4 alternate</td><td>FIPS 203 standard</td></tr>
            <tr><td>Ring structure</td><td>None</td><td>Module / ring</td></tr>
            <tr><td>Deployment</td><td>Niche, high-value</td><td>Default PQ KEM</td></tr>
          </tbody>
        </table>
      </article>

      <article class="card decision">
        <h3>Decision tree</h3>
        <p>Post-quantum TLS or general use → <strong>ML-KEM-768</strong>.</p>
        <p>Maximum conservatism and size is acceptable → <strong>FrodoKEM-976</strong>.</p>
        <p>Archive secrecy horizon 20+ years → <strong>FrodoKEM-1344</strong>.</p>
        <p>Need smallest keys and fastest operation → <strong>ML-KEM-512</strong>.</p>
        <p>Maximum assurance recommendation: <code>SS = KDF(SS_mlkem || SS_frodo)</code>.</p>
        <p>Kyber Vault cross-link: <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener">https://systemslibrarian.github.io/crypto-lab-kyber-vault/</a></p>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> Ring-LWE risk remains theoretical, not a known break. FrodoKEM is explicit insurance against future structural breakthroughs.
      </article>
    </section>

    <section class="panel ${state.activeTab === 'errors' ? 'visible' : ''}" id="panel-errors" role="tabpanel" aria-labelledby="tab-errors" ${state.activeTab !== 'errors' ? 'hidden' : ''}>
      <article class="card">
        <h2>Error distribution: where security lives</h2>
        <p>FrodoKEM uses discrete table-sampled errors approximating Gaussian behavior. Errors must be random enough for security and small enough for correctness.</p>
        <div class="controls">
          <button id="sample-errors">Sample 1000 errors</button>
          <button id="run-failure">Run toy decryption failure</button>
        </div>
        <p role="status" aria-live="polite">${state.errorSummary}</p>
        <p role="status" aria-live="polite">${state.failureSummary}</p>
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

      <article class="card callout">
        <strong>Why this matters:</strong> Error distributions are the bridge between LWE proofs and practical implementations. FrodoKEM chooses conservative parameters even at performance cost.
      </article>
    </section>

    <section class="panel ${state.activeTab === 'landscape' ? 'visible' : ''}" id="panel-landscape" role="tabpanel" aria-labelledby="tab-landscape" ${state.activeTab !== 'landscape' ? 'hidden' : ''}>
      <article class="card">
        <h2>FrodoKEM in the PQ KEM landscape</h2>
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
          <h3>Belt-and-suspenders recommendation</h3>
          <p>For most deployments, ML-KEM-768 is enough. For highest assurance, combine ML-KEM-768 + FrodoKEM-976.</p>
          <p>Hybrid secret derivation: <code>SS = KDF(SS_mlkem || SS_frodo)</code>. Security holds if either KEM remains secure.</p>
          <p>20-year horizon framing: FrodoKEM is explicit insurance against uncertain long-term structural risk.</p>
          <p>Deployment notes: FrodoKEM was originated at Microsoft Research and appears in high-assurance hybrid deployments such as Amazon s2n-tls options.</p>
        </div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> FrodoKEM is not the default KEM. It is the conservative option for secrets where long-term risk tolerance is near zero.
      </article>
    </section>

    <section class="panel ${state.activeTab === 'divide' ? 'visible' : ''}" id="panel-divide" role="tabpanel" aria-labelledby="tab-divide" ${state.activeTab !== 'divide' ? 'hidden' : ''}>

      <article class="card">
        <h2>Two Philosophies, One Problem</h2>
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
        <p>Algebraic lattice schemes gain their speed from a mathematical shortcut: polynomial ring arithmetic, accelerated by the Number Theoretic Transform (NTT). That same structure is an extra attack surface — one that the underlying plain-LWE hardness proof does not cover. Whether that gap will ever be exploited is unknown. That uncertainty is exactly what drives the structureless approach.</p>
      </article>

      <article class="card">
        <h2>S-Cloud+ and the Structureless Bet</h2>
        <blockquote>
          "International standards based on algebraic lattices have some degree of security degradation. But structureless cryptographic algorithms basically do not have this problem."
          <footer>— Wang Xiaoyun, Tsinghua University Institute for Advanced Study, National People's Congress, Beijing, March 2026</footer>
        </blockquote>
        <p>China's leading structureless algorithm candidate is S-Cloud+, developed by Chinese cryptographers and actively promoted as the domestic alternative to ML-KEM. Its design philosophy is the same as FrodoKEM: plain LWE over an integer matrix, no ring structure, no NTT. As of April 2026, S-Cloud+ does not have a public cryptographic specification — its parameter sets, key sizes, and exact security proofs are not yet published. What is known is its philosophical commitment: trade performance for the most conservative possible security foundation.</p>
        <p>In February 2025, China's Institute of Commercial Cryptography Standards (OSCCA) issued a global call for post-quantum algorithm proposals — a direct parallel to NIST's 2016 competition, with a distinctly different technical direction baked in. Wang Xiaoyun projected a three-to-five year timeline to domestic standards, with finance and energy sectors first in line for migration.</p>
        <p>The motivation is not purely mathematical. Every major technological power wants cryptographic independence — the ability to deploy standards it controls, audits, and trusts. China's earlier development of SM2, SM3, and SM4 (classical cryptography standards) and their mandatory domestic use established this pattern. S-Cloud+ is its post-quantum continuation.</p>
      </article>

      <article class="card">
        <h2>Even NIST Hedged</h2>
        <p>In March 2025, NIST selected <strong>HQC</strong> — a code-based algorithm using completely different mathematics (error-correcting codes, not lattices) — as a fourth backup standard. Dustin Moody, NIST's PQC project lead, stated the rationale directly: having a fallback in case ML-KEM proves vulnerable.</p>
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
  </main>
  `;

  appRoot.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      state.activeTab = button.dataset.tab as TabId;
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

  const themeButton = appRoot.querySelector<HTMLButtonElement>('#theme-toggle');
  if (themeButton) {
    themeButton.addEventListener('click', () => {
      const next: Theme = getTheme() === 'dark' ? 'light' : 'dark';
      setTheme(next);
      const nextMeta = themeMeta(next);
      themeButton.textContent = nextMeta.icon;
      themeButton.setAttribute('aria-label', nextMeta.label);
    });
  }

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
    state.lweSamples = buildToyLweSamples(state.lweSecret, true);
    state.lweCleanSamples = buildToyLweSamples(state.lweSecret, false);
    state.lweOutcome = 'Generated 5 noisy samples and 3 noiseless equations from the selected secret.';
    render();
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
    const p = FRODO[state.selectedParam];
    const start = performance.now();
    const pk = randomBytes(p.publicKey);
    const sk = randomBytes(p.privateKey);
    state.keygenMs = performance.now() - start;
    state.keygenPreview = hexPreview(pk, 64);
    state.keygenSkSize = sk.length;
    state.keygenRatio = `${p.label} public key (${p.publicKey} bytes) is ${(p.publicKey / 1184).toFixed(1)}x ML-KEM-768.`;
    render();
  });

  const kemGen = appRoot.querySelector<HTMLButtonElement>('#kem-gen');
  kemGen?.addEventListener('click', () => {
    state.aliceSeed = randomBytes(32);
    state.kemCiphertext = null;
    state.kemBobSecret = null;
    state.kemAliceSecret = null;
    state.kemEncapMs = 0;
    state.kemDecapMs = 0;
    state.kemStatus = 'Alice keypair generated. Bob can encapsulate now.';
    render();
  });

  const kemEncap = appRoot.querySelector<HTMLButtonElement>('#kem-encap');
  kemEncap?.addEventListener('click', async () => {
    if (!state.aliceSeed) {
      state.kemStatus = 'Generate Alice keypair first.';
      render();
      return;
    }
    const p = FRODO[state.selectedParam];
    const start = performance.now();
    const ct = randomBytes(p.ciphertext);
    const secret = await sha256(concat(state.aliceSeed, ct));
    state.kemEncapMs = performance.now() - start;
    state.kemCiphertext = ct;
    state.kemBobSecret = secret;
    state.kemAliceSecret = null;
    state.kemStatus = `Bob encapsulated using ${p.label}. Ciphertext size = ${p.ciphertext} bytes.`;
    render();
  });

  const kemDecap = appRoot.querySelector<HTMLButtonElement>('#kem-decap');
  kemDecap?.addEventListener('click', async () => {
    if (!state.aliceSeed || !state.kemCiphertext) {
      state.kemStatus = 'Encapsulate first.';
      render();
      return;
    }
    const start = performance.now();
    state.kemAliceSecret = await sha256(concat(state.aliceSeed, state.kemCiphertext));
    state.kemDecapMs = performance.now() - start;
    state.kemStatus = 'Alice decapsulated and derived a shared secret.';
    render();
  });

  const kemTamper = appRoot.querySelector<HTMLButtonElement>('#kem-tamper');
  kemTamper?.addEventListener('click', () => {
    if (!state.kemCiphertext) {
      state.kemStatus = 'No ciphertext to tamper.';
      render();
      return;
    }
    const idx = randomInt(state.kemCiphertext.length);
    state.kemCiphertext[idx] = state.kemCiphertext[idx] ^ 0x01;
    state.kemStatus = `Tampered ciphertext byte at index ${idx}. Next decapsulation should mismatch.`;
    render();
  });

  const runCompare = appRoot.querySelector<HTMLButtonElement>('#run-compare');
  runCompare?.addEventListener('click', () => {
    state.compareRows.frodo.keygen = estimateOperationMs(260000);
    state.compareRows.frodo.encaps = estimateOperationMs(220000);
    state.compareRows.frodo.decaps = estimateOperationMs(230000);

    state.compareRows.mlkem.keygen = estimateOperationMs(22000);
    state.compareRows.mlkem.encaps = estimateOperationMs(18000);
    state.compareRows.mlkem.decaps = estimateOperationMs(19000);

    state.compareBench = 'Side-by-side operation complete. Frodo path is intentionally heavier than ML-KEM path.';
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
}

state.lweSamples = buildToyLweSamples(state.lweSecret, true);
state.lweCleanSamples = buildToyLweSamples(state.lweSecret, false);
render();
