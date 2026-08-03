import { createHash } from 'node:crypto';
import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional regression gate for the claims the page makes on screen.
 *
 * The a11y spec proves the markup is reachable; this one proves it is TRUE.
 * Every assertion below is checked against a value the page itself computed —
 * the samples table is re-derived from the secret the learner typed, the size
 * calculator is evaluated from its own printed formula, the benchmark headline
 * is recomputed from the medians in its own table, the hybrid secret is
 * re-hashed from the two component secrets it displays — so a verdict that
 * drifts from its own arithmetic fails here rather than teaching a lie.
 *
 * Real FrodoKEM runs in WASM, so the crypto-heavy tests get generous timeouts
 * instead of weakened assertions.
 */

// ── Spec figures (FrodoKEM specification, Table 1). The page prints these in
// several places; the tests below cross-check the page against itself, and this
// table is the independent anchor for the eFrodoKEM-*-AES sizes liboqs returns.
const SETS = {
  frodo640: { label: 'FrodoKEM-640', n: 640, d: 15, pk: 9616, sk: 19888, ct: 9720, ss: 16, maxError: 12 },
  frodo976: { label: 'FrodoKEM-976', n: 976, d: 16, pk: 15632, sk: 31296, ct: 15744, ss: 24, maxError: 10 },
  frodo1344: { label: 'FrodoKEM-1344', n: 1344, d: 16, pk: 21520, sk: 43088, ct: 21632, ss: 32, maxError: 6 },
} as const;
type SetId = keyof typeof SETS;

const MLKEM768_PK = 1184;

const mod = (a: number, q: number): number => ((a % q) + q) % q;
const num = (s: string): number => Number(s.replace(/[, ]/g, ''));

/** The exhibit's own status line (never a checkpoint's feedback, which shares role=status). */
function status(page: Page, panel: string): Locator {
  return page.locator(`#panel-${panel} p[role="status"]:not(.cp-feedback)`);
}

async function openTab(page: Page, tab: string): Promise<void> {
  await page.click(`[data-tab="${tab}"]`);
  await expect(page.locator(`#panel-${tab}`)).toBeVisible();
}

/** Clicks an async (WASM-backed) control and waits for its busy state to clear. */
async function runAndSettle(page: Page, selector: string, timeout = 120_000): Promise<void> {
  await page.click(selector);
  await expect(page.locator(selector)).toBeEnabled({ timeout });
}

/** The five toy-LWE sample rows: [a0,a1,a2], b, e. */
async function readSamples(page: Page): Promise<Array<{ a: number[]; b: number; e: number }>> {
  return page
    .locator('#panel-lwe table:not(.bridge-table) tbody tr')
    .evaluateAll((rows) =>
      rows.map((row) => {
        const cells = Array.from(row.querySelectorAll('td'), (td) => td.textContent ?? '');
        return {
          a: (cells[1].match(/-?\d+/g) ?? []).map(Number),
          b: Number(cells[2]),
          e: Number(cells[3]),
        };
      }),
    );
}

/**
 * Generates samples and solves them, retrying past the ~1% of random 3×3
 * systems over Z_97 that are singular (the page says so and asks for new
 * samples — an honest outcome, but not the one under test here).
 */
async function generateAndSolve(
  page: Page,
  button: '#solve-clean' | '#solve-noisy',
): Promise<{ text: string; rows: Array<{ a: number[]; b: number; e: number }> }> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await page.click('#gen-samples');
    const rows = await readSamples(page);
    await page.click(button);
    const text = await status(page, 'lwe').innerText();
    if (!text.includes('singular')) return { text, rows };
  }
  throw new Error(`${button} produced a singular system 8 times running`);
}

async function setSecret(page: Page, s: [number, number, number]): Promise<void> {
  await page.locator('#s0').fill(String(s[0]));
  await page.locator('#s1').fill(String(s[1]));
  await page.locator('#s2').fill(String(s[2]));
}

// ───────────────────────────────────────────────────────────────────────────
// Exhibit 1 — the toy LWE problem
// ───────────────────────────────────────────────────────────────────────────

test('exhibit 1: every generated sample really satisfies b = <a,s> + e mod 97', async ({ page }) => {
  await page.goto('.');
  const secret: [number, number, number] = [5, 13, 42];
  await setSecret(page, secret);
  await page.click('#gen-samples');
  await expect(status(page, 'lwe')).toContainText('Generated 5 noisy samples');

  const rows = await readSamples(page);
  expect(rows).toHaveLength(5);
  for (const { a, b, e } of rows) {
    expect(a).toHaveLength(3);
    for (const ai of a) expect(ai).toBeGreaterThanOrEqual(0);
    for (const ai of a) expect(ai).toBeLessThanOrEqual(96);
    // The displayed b is the displayed a, s and e — not a decorative number.
    expect(mod(a[0] * secret[0] + a[1] * secret[1] + a[2] * secret[2] + e, 97)).toBe(b);
    // Default error magnitude is 1, so e ∈ {-1, 0, 1} exactly as the copy says.
    expect(Math.abs(e)).toBeLessThanOrEqual(1);
  }
});

test('exhibit 1: noiseless elimination recovers exactly the secret the learner entered', async ({ page }) => {
  await page.goto('.');
  const secret: [number, number, number] = [17, 3, 91];
  await setSecret(page, secret);
  const { text } = await generateAndSolve(page, '#solve-clean');
  expect(text).toContain('Without noise, Gaussian elimination recovers');
  const solved = (text.match(/\[([^\]]+)\]/)?.[1] ?? '').split(',').map((v) => Number(v.trim()));
  expect(solved).toEqual(secret);
});

test('exhibit 1: the noisy verdict matches the residuals it prints', async ({ page }) => {
  await page.goto('.');
  await setSecret(page, [8, 8, 8]);
  await page.locator('#noise-mag').fill('6');
  const { text, rows } = await generateAndSolve(page, '#solve-noisy');
  if (text.includes('happened to fit exactly')) {
    // Honest fallback branch: only legitimate when nothing is inconsistent.
    return;
  }
  expect(text).toContain('equations become inconsistent');
  const candidate = (text.match(/Candidate s = \[([^\]]+)\]/)?.[1] ?? '').split(',').map((v) => Number(v.trim()));
  const residuals = (text.match(/residuals = \[([^\]]+)\]/)?.[1] ?? '').split(',').map((v) => Number(v.trim()));
  expect(candidate).toHaveLength(3);
  expect(residuals).toHaveLength(rows.length);
  // Each printed residual is <a, candidate> - b mod 97 for the displayed sample.
  rows.forEach(({ a, b }, i) => {
    expect(mod(a[0] * candidate[0] + a[1] * candidate[1] + a[2] * candidate[2] - b, 97)).toBe(residuals[i]);
  });
  // The first three equations are the ones that were solved, so they must fit;
  // "inconsistent" is only true if a later one does not.
  expect(residuals.slice(0, 3)).toEqual([0, 0, 0]);
  expect(residuals.slice(3).some((r) => r !== 0)).toBe(true);
});

test('exhibit 1: the noise slider bounds the errors and labels its own regime', async ({ page }) => {
  await page.goto('.');
  await page.click('#gen-samples');

  for (const [mag, label] of [
    ['0', 'No noise'],
    ['3', 'Small (solvable)'],
    ['12', 'Medium (hard)'],
    ['20', 'Large (impossible)'],
  ] as const) {
    await page.locator('#noise-mag').fill(mag);
    await expect(page.locator('.noise-slider-wrap')).toContainText(label);
    await expect(page.locator('.noise-slider-wrap label')).toContainText(`Error magnitude: ${mag}`);
    const rows = await readSamples(page);
    expect(rows).toHaveLength(5);
    for (const { e } of rows) expect(Math.abs(e)).toBeLessThanOrEqual(Number(mag));
    if (mag === '0') for (const { e } of rows) expect(e).toBe(0);
  }
});

test('exhibit 1: guards fire once the samples are cleared', async ({ page }) => {
  await page.goto('.');
  await page.click('#rand-secret');
  await expect(status(page, 'lwe')).toContainText('Secret randomized to');

  // Randomizing invalidates BOTH sample sets: neither solver may answer with a
  // stale secret from before the randomization.
  await page.click('#solve-noisy');
  await expect(status(page, 'lwe')).toHaveText('Generate noisy samples first.');
  await page.click('#solve-clean');
  await expect(status(page, 'lwe')).toHaveText('Generate samples first.');

  // …and after regenerating, the clean solve answers with the NEW secret.
  const s = await page.evaluate(() =>
    ['s0', 's1', 's2'].map((id) => Number((document.getElementById(id) as HTMLInputElement).value)),
  );
  const { text } = await generateAndSolve(page, '#solve-clean');
  expect(text).toContain('Without noise, Gaussian elimination recovers');
  const solved = (text.match(/\[([^\]]+)\]/)?.[1] ?? '').split(',').map((v) => Number(v.trim()));
  expect(solved).toEqual(s);
});

test('exhibit 1: the animated A·s + e = b really computes b', async ({ page }) => {
  test.setTimeout(60_000);
  await page.goto('.');
  await setSecret(page, [4, 9, 61]);
  await page.locator('#noise-mag').fill('0'); // e = 0 makes the frame exactly checkable
  await page.click('#gen-samples');
  await page.click('#run-matrix-anim');
  await expect(page.locator('#matrix-anim-container')).toContainText('Complete! All b values computed.', {
    timeout: 30_000,
  });

  const frame = await page.evaluate(() => {
    const grid = document.querySelector('.matrix-viz div[style*="grid"]');
    const cols = Array.from(grid?.children ?? []);
    const nums = (el: Element | undefined) =>
      Array.from(el?.querySelectorAll('.matrix-cell') ?? [], (c) => Number(c.textContent));
    return { A: nums(cols[0]), s: nums(cols[1]), b: nums(cols[2]) };
  });
  expect(frame.A).toHaveLength(9);
  expect(frame.s).toEqual([4, 9, 61]);
  expect(frame.b).toHaveLength(3);
  for (let r = 0; r < 3; r += 1) {
    const dot = frame.A[r * 3] * frame.s[0] + frame.A[r * 3 + 1] * frame.s[1] + frame.A[r * 3 + 2] * frame.s[2];
    expect(mod(dot, 97)).toBe(frame.b[r]);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// Exhibit 2 — key generation and the size calculator
// ───────────────────────────────────────────────────────────────────────────

test('exhibit 2: the size calculator is arithmetically true for all three sets', async ({ page }) => {
  await page.goto('.');
  await openTab(page, 'keygen');

  for (const id of Object.keys(SETS) as SetId[]) {
    const set = SETS[id];
    await page.selectOption('#param-select', id);
    const calc = await page.locator('#panel-keygen .size-calc').innerText();
    // Three worked lines, one per key part, each prefixed with the set's label.
    const lines = calc.split('\n').filter((l) => l.startsWith(`${set.label}:`));
    expect(lines, `worked lines for ${set.label}`).toHaveLength(3);
    const [pkLine, skLine, ctLine] = lines;

    // pk: "16 + 976 × 8 × 16/8 = 15,632 bytes ✓"
    const pk = pkLine.match(/16 \+ ([\d,]+) × 8 × (\d+)\/8 = ([\d,]+) bytes (.)/);
    expect(pk, `pk formula for ${set.label}`).not.toBeNull();
    expect(num(pk![1])).toBe(set.n);
    expect(Number(pk![2])).toBe(set.d);
    expect(16 + (set.n * 8 * set.d) / 8).toBe(num(pk![3]));
    expect(num(pk![3])).toBe(set.pk);
    expect(pk![4]).toBe('✓');

    // sk: "24 + 15,632 + 976 × 8 × 2 + 24 = 31,296 bytes ✓"
    const sk = skLine.match(/(\d+) \+ ([\d,]+) \+ ([\d,]+) × 8 × 2 \+ (\d+) = ([\d,]+) bytes (.)/);
    expect(sk, `sk formula for ${set.label}`).not.toBeNull();
    expect(Number(sk![1]) + num(sk![2]) + num(sk![3]) * 8 * 2 + Number(sk![4])).toBe(num(sk![5]));
    expect(num(sk![2])).toBe(set.pk);
    expect(num(sk![5])).toBe(set.sk);
    expect(sk![6]).toBe('✓');

    // ct: "15,616 + 128 = 15,744 bytes ✓"
    const ct = ctLine.match(/([\d,]+) \+ ([\d,]+) = ([\d,]+) bytes (.)/);
    expect(ct, `ct formula for ${set.label}`).not.toBeNull();
    expect(num(ct![1]) + num(ct![2])).toBe(num(ct![3]));
    expect(num(ct![1])).toBe((8 * set.n * set.d) / 8);
    expect(num(ct![2])).toBe((8 * 8 * set.d) / 8);
    expect(num(ct![3])).toBe(set.ct);
    expect(ct![4]).toBe('✓');

    // …and the calculator agrees with the spec table printed beside it.
    const row = page.locator('#panel-keygen tbody tr', { hasText: set.label }).first();
    await expect(row).toContainText(`${set.pk.toLocaleString('en-US')} bytes`);
    await expect(row).toContainText(`${set.sk.toLocaleString('en-US')} bytes`);
  }
});

test('exhibit 2: real liboqs keygen returns the sizes the page advertises', async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto('.');
  await openTab(page, 'keygen');

  for (const id of Object.keys(SETS) as SetId[]) {
    const set = SETS[id];
    await page.selectOption('#param-select', id);
    await runAndSettle(page, '#run-keygen');

    const panel = page.locator('#panel-keygen .grid-two > div').first();
    const text = await panel.innerText();

    // "…<128 hex chars>... [15,568 more bytes]" — shown + hidden must be the whole key.
    const preview = text.match(/preview: ([0-9a-f]+)\.\.\. \[(\d+) more bytes\]/);
    expect(preview, `preview for ${set.label}`).not.toBeNull();
    expect(preview![1]).toHaveLength(128);
    expect(64 + Number(preview![2])).toBe(set.pk);

    expect(text).toContain(`Private key size: ${set.sk} bytes`);
    const ms = text.match(/Generation time: ([\d.]+) ms/);
    expect(ms, `generation time for ${set.label}`).not.toBeNull();
    expect(Number(ms![1])).toBeGreaterThan(0);

    // The ratio sentence is the pk it just generated over the ML-KEM-768 figure
    // the bar chart prints — not a hardcoded number.
    const ratio = text.match(/public key \(([\d,]+) bytes\) is ([\d.]+)× the size/);
    expect(ratio, `ratio sentence for ${set.label}`).not.toBeNull();
    expect(num(ratio![1])).toBe(set.pk);
    expect(Number(ratio![2])).toBeCloseTo(set.pk / MLKEM768_PK, 1);

    const bars = await page.locator('#panel-keygen .grid-two > div').nth(1).innerText();
    expect(bars).toContain(`ML-KEM-768: ${MLKEM768_PK.toLocaleString('en-US')} bytes`);
    expect(bars).toContain(`${set.label}: ${set.pk.toLocaleString('en-US')} bytes`);
    const barRatio = bars.match(/about ([\d.]+)× larger/);
    expect(Number(barRatio![1])).toBeCloseTo(set.pk / MLKEM768_PK, 1);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// Exhibit 3 — encapsulation / decapsulation and the tamper path
// ───────────────────────────────────────────────────────────────────────────

test('exhibit 3: the KEM round-trip derives one identical secret on both sides', async ({ page }) => {
  test.setTimeout(180_000);
  const set = SETS.frodo976;
  await page.goto('.');
  await openTab(page, 'kem');

  await runAndSettle(page, '#kem-gen');
  await expect(status(page, 'kem')).toContainText(
    `Alice's real ${set.label} keypair is ready (pk ${set.pk.toLocaleString('en-US')} B, sk ${set.sk.toLocaleString('en-US')} B)`,
  );

  await runAndSettle(page, '#kem-encap');
  await expect(status(page, 'kem')).toContainText(
    `ciphertext ${set.ct.toLocaleString('en-US')} B, shared secret ${set.ss} B`,
  );

  await runAndSettle(page, '#kem-decap');
  await expect(status(page, 'kem')).toHaveText(
    'Alice decapsulated and recovered the identical shared secret — the KEM round-trip succeeded.',
  );

  const panel = page.locator('#panel-kem .grid-two > div').first();
  const text = await panel.innerText();

  const ctPreview = text.match(/Ciphertext preview: ([0-9a-f]+)\.\.\. \[(\d+) more bytes\]/);
  expect(ctPreview).not.toBeNull();
  expect(64 + Number(ctPreview![2])).toBe(set.ct);

  const bob = text.match(/Bob shared secret \((\d+) bytes\): ([0-9a-f]+)/);
  const alice = text.match(/Alice shared secret \((\d+) bytes\): ([0-9a-f]+)/);
  expect(bob).not.toBeNull();
  expect(alice).not.toBeNull();
  expect(Number(bob![1])).toBe(set.ss);
  expect(Number(alice![1])).toBe(set.ss);
  expect(bob![2]).toHaveLength(set.ss * 2);
  // The headline claim of the whole exhibit: the two sides agree byte for byte.
  expect(alice![2]).toBe(bob![2]);
  expect(alice![2]).not.toMatch(/^0+$/);

  for (const label of ['Encapsulation time', 'Decapsulation time']) {
    const ms = text.match(new RegExp(`${label}: ([\\d.]+) ms`));
    expect(ms, label).not.toBeNull();
    expect(Number(ms![1])).toBeGreaterThan(0);
  }

  await expect(page.locator('#panel-kem .status-ok')).toHaveText('✓ Secrets match');
  await expect(page.locator('#panel-kem .status-bad')).toHaveCount(0);
  // The data-flow diagram agrees with the verdict, and nothing is marked tampered.
  await expect(page.locator('.kem-flow')).toContainText('derives SSA ✓');
  await expect(page.locator('.flow-wire .wire.tampered')).toHaveCount(0);

  // The shared-secret size the comparison exhibit advertises is the one just measured.
  await openTab(page, 'compare');
  await expect(page.locator('#panel-compare tbody tr', { hasText: 'Shared secret' })).toContainText(
    `${set.ss} bytes`,
  );
});

test('exhibit 3: a tampered ciphertext reaches implicit rejection and says why', async ({ page }) => {
  test.setTimeout(180_000);
  const set = SETS.frodo976;
  await page.goto('.');
  await openTab(page, 'kem');

  await runAndSettle(page, '#kem-gen');
  await runAndSettle(page, '#kem-encap');
  await runAndSettle(page, '#kem-decap');
  const good = await page.locator('#panel-kem .grid-two > div').first().innerText();
  const goodAlice = good.match(/Alice shared secret \(\d+ bytes\): ([0-9a-f]+)/)![1];

  await page.click('#kem-tamper');
  const tamperText = await status(page, 'kem').innerText();
  const idx = Number(tamperText.match(/at byte (\d+)/)?.[1]);
  expect(Number.isFinite(idx)).toBe(true);
  expect(idx).toBeGreaterThanOrEqual(0);
  expect(idx).toBeLessThan(set.ct);
  expect(tamperText).toContain('implicit rejection');
  await expect(page.locator('.flow-wire .wire.tampered')).toHaveCount(2);
  await expect(page.locator('.flow-wire')).toContainText('ct (tampered)');

  await runAndSettle(page, '#kem-decap');
  const failed = status(page, 'kem');
  // Reaches the failure state…
  await expect(failed).toContainText('the secret does NOT match');
  // …and says why.
  await expect(failed).toContainText('FrodoKEM detected the tampered ciphertext');
  await expect(failed).toContainText('implicit-rejection secret');

  const text = await page.locator('#panel-kem .grid-two > div').first().innerText();
  const bob = text.match(/Bob shared secret \((\d+) bytes\): ([0-9a-f]+)/)!;
  const alice = text.match(/Alice shared secret \((\d+) bytes\): ([0-9a-f]+)/)!;
  expect(Number(alice[1])).toBe(set.ss);
  // Implicit rejection returns a full-length pseudorandom secret, not an error
  // and not a truncated/zero value — and it differs from the honest one.
  expect(alice[2]).toHaveLength(set.ss * 2);
  expect(alice[2]).not.toBe(bob[2]);
  expect(alice[2]).not.toBe(goodAlice);
  expect(alice[2]).not.toMatch(/^0+$/);
  await expect(page.locator('#panel-kem .status-bad')).toHaveText('✗ Secrets mismatch');
  await expect(page.locator('#panel-kem .status-ok')).toHaveCount(0);

  // The byte-diff view highlights the flipped byte and accounts for every byte
  // of the ciphertext: skipped prefix + shown window + skipped suffix = ct size.
  const diff = await page.locator('.ct-diff').innerText();
  const skipped = Number(diff.match(/\[bytes 0–(\d+)\]/)?.[1] ?? -1) + 1;
  const trailing = Number(diff.match(/\[(\d+) more\]/)?.[1] ?? 0);
  const shownHex = diff.replace(/\.\.\. \[[^\]]+\]/g, '').replace(/\s+/g, '');
  expect(shownHex).toMatch(/^[0-9a-f]+$/);
  expect(shownHex.length % 2).toBe(0);
  expect(skipped + shownHex.length / 2 + trailing).toBe(set.ct);
  expect(idx).toBeGreaterThanOrEqual(skipped);
  expect(idx).toBeLessThan(skipped + shownHex.length / 2);
  await expect(page.locator('.ct-diff .tampered')).toHaveCount(1);
});

test('exhibit 3: each step refuses to run out of order and says what is missing', async ({ page }) => {
  await page.goto('.');
  await openTab(page, 'kem');

  await page.click('#kem-encap');
  await expect(status(page, 'kem')).toHaveText('Generate Alice keypair first.');
  await page.click('#kem-decap');
  await expect(status(page, 'kem')).toHaveText('Encapsulate first.');
  await page.click('#kem-tamper');
  await expect(status(page, 'kem')).toHaveText('No ciphertext to tamper.');
  await expect(page.locator('#panel-kem .status-ok, #panel-kem .status-bad')).toHaveText('--');
});

test('exhibit 3: FrodoKEM-1344 encapsulates at its own spec sizes', async ({ page }) => {
  test.setTimeout(180_000);
  const set = SETS.frodo1344;
  await page.goto('.');
  await openTab(page, 'keygen');
  await page.selectOption('#param-select', 'frodo1344');
  await openTab(page, 'kem');

  await runAndSettle(page, '#kem-gen');
  await expect(status(page, 'kem')).toContainText(`Alice's real ${set.label} keypair is ready`);
  await runAndSettle(page, '#kem-encap');
  await expect(status(page, 'kem')).toContainText(
    `ciphertext ${set.ct.toLocaleString('en-US')} B, shared secret ${set.ss} B`,
  );
  await runAndSettle(page, '#kem-decap');
  await expect(status(page, 'kem')).toContainText('the KEM round-trip succeeded');

  const text = await page.locator('#panel-kem .grid-two > div').first().innerText();
  const ct = text.match(/Ciphertext preview: [0-9a-f]+\.\.\. \[(\d+) more bytes\]/)!;
  expect(64 + Number(ct[1])).toBe(set.ct);
  const alice = text.match(/Alice shared secret \((\d+) bytes\): ([0-9a-f]+)/)!;
  expect(Number(alice[1])).toBe(set.ss);
  await expect(page.locator('#panel-kem .status-ok')).toHaveText('✓ Secrets match');
});

// ───────────────────────────────────────────────────────────────────────────
// Exhibit 4 — measured benchmark and the hybrid derivation
// ───────────────────────────────────────────────────────────────────────────

test('exhibit 4: the benchmark headline is the ratio of the medians in its own table', async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto('.');
  await openTab(page, 'compare');
  await runAndSettle(page, '#run-compare');

  const headline = await status(page, 'compare').first().innerText();
  expect(headline).toContain('Measured on this device');
  const ratio = Number(headline.match(/≈([\d.]+)× ML-KEM-768/)?.[1]);
  expect(Number.isFinite(ratio)).toBe(true);

  const cell = async (op: string, col: 1 | 2): Promise<{ median: number; min: number; max: number }> => {
    const raw = await page
      .locator('#panel-compare tbody tr', { hasText: op })
      .locator('td')
      .nth(col)
      .innerText();
    const m = raw.match(/([\d.]+) ms \(([\d.]+)–([\d.]+)\)/);
    expect(m, `${op} column ${col}`).not.toBeNull();
    return { median: Number(m![1]), min: Number(m![2]), max: Number(m![3]) };
  };

  for (const op of ['Key generation', 'Encapsulation', 'Decapsulation']) {
    const frodo = await cell(op, 1);
    const mlkem = await cell(op, 2);
    for (const [name, s] of [['frodo', frodo], ['mlkem', mlkem]] as const) {
      // A median outside its own min–max range would be an impossible statistic.
      expect(s.min, `${op} ${name} min<=median`).toBeLessThanOrEqual(s.median);
      expect(s.median, `${op} ${name} median<=max`).toBeLessThanOrEqual(s.max);
      expect(s.min).toBeGreaterThanOrEqual(0);
    }
    // The exhibit's thesis: unstructured FrodoKEM is slower than NTT ML-KEM.
    expect(frodo.median, `${op}: FrodoKEM should be slower`).toBeGreaterThan(mlkem.median);
  }

  const frodoKeygen = await cell('Key generation', 1);
  const mlkemKeygen = await cell('Key generation', 2);
  expect(ratio).toBeGreaterThan(1);
  if (mlkemKeygen.median >= 0.05) {
    // Both table cells are rounded to 3 dp and the headline to 1 dp; widen the
    // recomputed bounds by exactly that much rather than by a fudge factor.
    const lo = (frodoKeygen.median - 0.0005) / (mlkemKeygen.median + 0.0005) - 0.05;
    const hi = (frodoKeygen.median + 0.0005) / (mlkemKeygen.median - 0.0005) + 0.05;
    expect(ratio).toBeGreaterThanOrEqual(lo);
    expect(ratio).toBeLessThanOrEqual(hi);
  }

  await expect(page.locator('#panel-compare .bench-method').first()).toContainText(
    'Method: 2 warm-up run(s) discarded, then 11 measured samples per operation.',
  );
});

test('exhibit 4: the hybrid secret really is SHA-256(SS_mlkem ∥ SS_frodo)', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('.');
  await openTab(page, 'compare');
  await runAndSettle(page, '#run-hybrid');

  const box = await page.locator('.hybrid-box').innerText();
  const hexes = box.match(/[0-9a-f]{32,}/g) ?? [];
  expect(hexes).toHaveLength(3);
  const [mlkem, frodo, hybrid] = hexes;
  expect(mlkem).toHaveLength(64); // ML-KEM-768: 32-byte shared secret
  expect(frodo).toHaveLength(48); // FrodoKEM-976: 24-byte shared secret
  expect(hybrid).toHaveLength(64); // SHA-256 output
  expect(mlkem).not.toBe(frodo);

  const expected = createHash('sha256')
    .update(Buffer.from(mlkem, 'hex'))
    .update(Buffer.from(frodo, 'hex'))
    .digest('hex');
  expect(hybrid).toBe(expected);

  await expect(status(page, 'compare').last()).toContainText(
    'SHA-256(32-byte ML-KEM secret ∥ 24-byte FrodoKEM secret) → 32 bytes',
  );
});

// ───────────────────────────────────────────────────────────────────────────
// Exhibit 5 — error distribution and decryption failure
// ───────────────────────────────────────────────────────────────────────────

test('exhibit 5: the histogram bins account for all 1000 samples', async ({ page }) => {
  await page.goto('.');

  for (const id of ['frodo976', 'frodo640'] as SetId[]) {
    const set = SETS[id];
    await openTab(page, 'keygen');
    await page.selectOption('#param-select', id);
    await openTab(page, 'errors');
    await page.click('#sample-errors');
    await expect(status(page, 'errors').first()).toHaveText(
      `Sampled 1000 errors for ${set.label}. Distribution is centered near 0 with thin tails.`,
    );

    const bins = await page.locator('.histogram .hist-row').evaluateAll((rows) =>
      rows.map((row) => {
        const spans = row.querySelectorAll('span');
        return { value: Number(spans[0].textContent), count: Number(spans[1].textContent) };
      }),
    );
    // One bin per representable error, spanning exactly ±maxError for this set.
    expect(bins).toHaveLength(2 * set.maxError + 1);
    expect(bins[0].value).toBe(-set.maxError);
    expect(bins[bins.length - 1].value).toBe(set.maxError);
    // The parts sum to the whole the summary line claims.
    expect(bins.reduce((t, b) => t + b.count, 0)).toBe(1000);
    for (const b of bins) expect(b.count).toBeGreaterThanOrEqual(0);
    // "centered near 0": the modal bin is within one step of zero.
    const peak = bins.reduce((a, b) => (b.count > a.count ? b : a));
    expect(Math.abs(peak.value)).toBeLessThanOrEqual(1);
    await expect(page.locator('#panel-errors h3').first()).toContainText(set.label);
  }
});

test('exhibit 5: the toy decryption failure it reports is a real decode failure', async ({ page }) => {
  await page.goto('.');
  await openTab(page, 'errors');

  const line = status(page, 'errors').last();
  let text = '';
  // ~35% of draws per try produce no failure in 25 tries only with probability
  // ~3e-5; retrying a handful of times makes the test deterministic in practice.
  for (let i = 0; i < 6; i += 1) {
    await page.click('#run-failure');
    text = await line.innerText();
    if (text.startsWith('Toy failure observed')) break;
    expect(text).toContain('No failure occurred in 25 tries');
  }
  expect(text).toContain('Toy failure observed');

  const m = text.match(
    /message=(\d+), encoded=(\d+) mod (\d+), accumulated error=(-?\d+), recovered=(\d+)/,
  );
  expect(m, 'failure line shape').not.toBeNull();
  const [, mRaw, encRaw, qRaw, errRaw, recRaw] = m!;
  const message = Number(mRaw);
  const encoded = Number(encRaw);
  const q = Number(qRaw);
  const err = Number(errRaw);
  const recovered = Number(recRaw);
  const half = Math.floor(q / 2);

  expect(q).toBe(17);
  expect([0, 1]).toContain(message);
  expect(Math.abs(err)).toBeLessThanOrEqual(6);
  // The encoded value is the message it printed, shifted by the error it printed.
  expect(encoded).toBe(mod(message * half + err, q));
  // The recovered bit is nearest-neighbour decoding of that same value…
  const d0 = Math.min(mod(encoded, q), mod(-encoded, q));
  const d1 = Math.min(mod(encoded - half, q), mod(half - encoded, q));
  expect(recovered).toBe(d1 < d0 ? 1 : 0);
  // …and it disagrees with the message, which is what makes it a failure.
  expect(recovered).not.toBe(message);
});

test('exhibit 5: the failure-probability chart shows the cliff it describes', async ({ page }) => {
  await page.goto('.');
  await openTab(page, 'errors');
  await page.click('#run-fail-chart');

  const rows = await page.locator('.fail-chart .fail-row').evaluateAll((els) =>
    els.map((el) => {
      const spans = el.querySelectorAll('span');
      return {
        maxErr: Number((spans[0].textContent ?? '').replace('±', '')),
        pct: Number((spans[1].textContent ?? '').replace('%', '')),
        cls: el.querySelector('.fail-fill')?.className ?? '',
      };
    }),
  );

  expect(rows).toHaveLength(8);
  expect(rows.map((r) => r.maxErr)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  for (const r of rows) {
    expect(r.pct).toBeGreaterThanOrEqual(0);
    expect(r.pct).toBeLessThanOrEqual(100);
    // Each bar's colour band is the one its own percentage earns.
    const expected = r.pct === 0 ? 'safe' : r.pct < 15 ? 'risky' : 'broken';
    expect(r.cls, `±${r.maxErr} at ${r.pct}% should be ${expected}`).toContain(expected);
  }
  // At q=17 with half=8, an error of ±3 can never cross the decision boundary,
  // so these are exactly zero, not merely small.
  for (const r of rows.slice(0, 3)) expect(r.pct, `±${r.maxErr}`).toBe(0);
  // …and by ±8 decoding is broken. Expectation is ~49% over 500 trials.
  expect(rows[7].pct).toBeGreaterThan(25);
  expect(rows[7].pct).toBeGreaterThan(rows[3].pct + 10);
});

// ───────────────────────────────────────────────────────────────────────────
// Cross-cutting: navigation and the predict-before-you-run checkpoints
// ───────────────────────────────────────────────────────────────────────────

test('the seven exhibits are all reachable and deep-linkable', async ({ page }) => {
  const tabs = ['lwe', 'keygen', 'kem', 'compare', 'errors', 'landscape', 'divide'];
  await page.goto('.');
  await expect(page.locator('[role="tab"]')).toHaveCount(tabs.length);

  for (const tab of tabs) {
    await openTab(page, tab);
    await expect(page.locator(`#tab-${tab}`)).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator(`#panel-${tab} .objective`)).toContainText('Goal');
    await expect(page.locator(`#panel-${tab} .takeaway`)).toContainText('You should now understand');
    // Exactly one panel is visible at a time.
    await expect(page.locator('.panel:visible')).toHaveCount(1);
    expect(page.url()).toContain(`#${tab}`);
  }

  // Deep link straight into an exhibit.
  await page.goto('#divide');
  await expect(page.locator('#panel-divide')).toBeVisible();
  await expect(page.locator('#panel-lwe')).toBeHidden();

  // Arrow keys move along the tablist and switch panels.
  await page.locator('#tab-divide').focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('#panel-lwe')).toBeVisible();
});

test('prediction checkpoints grade the answer and explain either way', async ({ page }) => {
  await page.goto('.');
  const cases = [
    { tab: 'lwe', id: 'lwe-clean', correct: 'yes', wrong: 'no', explains: 'ordinary linear system' },
    { tab: 'kem', id: 'kem-tamper', correct: 'no', wrong: 'yes', explains: 'Fujisaki' },
    { tab: 'errors', id: 'errors-failure', correct: 'fails', wrong: 'fine', explains: 'halfway decision boundary' },
  ] as const;

  // Wrong answers are told they are wrong — and still get the explanation.
  for (const c of cases) {
    await openTab(page, c.tab);
    await page.click(`[data-checkpoint="${c.id}"][data-choice="${c.wrong}"]`);
    const feedback = page.locator(`#panel-${c.tab} .cp-feedback`).first();
    await expect(feedback).toContainText('Not quite');
    await expect(feedback).toContainText(c.explains);
    await expect(feedback).toHaveClass(/off/);
    // Answering locks the choice so a learner cannot silently re-guess.
    await expect(page.locator(`[data-checkpoint="${c.id}"]`).first()).toBeDisabled();
  }

  // Correct answers are confirmed, with the same explanation.
  await page.goto('.');
  for (const c of cases) {
    await openTab(page, c.tab);
    await page.click(`[data-checkpoint="${c.id}"][data-choice="${c.correct}"]`);
    const feedback = page.locator(`#panel-${c.tab} .cp-feedback`).first();
    await expect(feedback).toContainText('✓ Correct.');
    await expect(feedback).toContainText(c.explains);
    await expect(feedback).toHaveClass(/ok/);
  }
});
