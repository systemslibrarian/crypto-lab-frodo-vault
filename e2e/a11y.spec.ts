import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the NIST KAT vectors;
 * this gates them on accessibility the same way. Scans the full page in both
 * themes with every collapsible / hidden region revealed.
 *
 * The seven exhibits are ARIA tabpanels: only the active one is shown, the
 * rest carry the `hidden` attribute (and lack `.visible`). To scan every
 * exhibit's markup we reveal all panels up front, open every <details>
 * (the "reality" panels), open every class-toggled `.collapsible-body`, and
 * neutralize animation/transition so nothing is scanned mid-flight.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const matches = await page.evaluate(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  expect(matches).toBe(true);
  await page.waitForFunction(() => document.getAnimations().every(a => a.playState !== 'running'));
}

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Open every <details> (reality panels).
    for (const d of document.querySelectorAll('details')) {
      (d as HTMLDetailsElement).open = true;
    }
    // Reveal every ARIA tabpanel: drop the `hidden` attribute and add the
    // display-granting `.visible` class so all seven exhibits render.
    for (const p of document.querySelectorAll<HTMLElement>('.panel')) {
      p.removeAttribute('hidden');
      p.classList.add('visible');
    }
    // Open every class-toggled collapsible body (glossary, decision tree, etc.).
    for (const c of document.querySelectorAll<HTMLElement>('.collapsible-body')) {
      c.classList.add('open');
    }
    // Clear any residual inline display:none.
    for (const el of document.querySelectorAll<HTMLElement>('[style*="display"]')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
  });
}

/**
 * WCAG 1.4.11 (non-text contrast) regression for text-entry control boundaries.
 * Axe does not flag low-contrast control borders, so we measure them directly:
 * every visible select/number-input's rendered border color must reach 3:1
 * against both the control's own fill and the first opaque ancestor surface
 * behind it. Translucent colors are composited against those surfaces first.
 */
async function minimumControlBoundaryRatio(page: Page): Promise<number> {
  return page
    .locator('select:visible, input[type="number"]:visible')
    .evaluateAll((elements) => {
      const parse = (value: string): { c: number[]; a: number } => {
        const n = (value.match(/[\d.]+/g) ?? ['0', '0', '0']).map(Number);
        return { c: n.slice(0, 3), a: n[3] ?? 1 };
      };
      const luminance = (parts: number[]): number => {
        const c = parts.map((part) => {
          const v = part / 255;
          return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
        });
        return 0.2126 * (c[0] ?? 0) + 0.7152 * (c[1] ?? 0) + 0.0722 * (c[2] ?? 0);
      };
      const ratio = (a: number[], b: number[]): number => {
        const [la, lb] = [luminance(a), luminance(b)];
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
      };
      const composite = (fg: number[], alpha: number, bg: number[]): number[] =>
        fg.map((v, i) => v * alpha + (bg[i] ?? 0) * (1 - alpha));
      const surfaceBehind = (el: Element): number[] => {
        for (let node = el.parentElement; node; node = node.parentElement) {
          const bg = parse(getComputedStyle(node).backgroundColor);
          if (bg.a >= 1) return bg.c;
        }
        return [255, 255, 255];
      };
      return Math.min(
        ...elements.map((el) => {
          const style = getComputedStyle(el);
          const exterior = surfaceBehind(el);
          const bg = parse(style.backgroundColor);
          const fill = bg.a >= 1 ? bg.c : composite(bg.c, bg.a, exterior);
          const b = parse(style.borderTopColor);
          const border = b.a >= 1 ? b.c : composite(b.c, b.a, fill);
          return Math.min(ratio(border, fill), ratio(border, exterior));
        }),
      );
    });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function runSuite(page: Page): Promise<void> {
  await expect(page.locator('h1')).toBeVisible();
  await revealAll(page);
  await neutralizeMotion(page);
  expect(await minimumControlBoundaryRatio(page)).toBeGreaterThanOrEqual(3);
  await scan(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await runSuite(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runSuite(page);
});
