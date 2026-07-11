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
  await page.addStyleTag({
    content:
      '*, *::before, *::after { animation: none !important; transition: none !important; }',
  });
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
  await revealAll(page);
  await neutralizeMotion(page);
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
