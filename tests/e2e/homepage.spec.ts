import { test, expect } from '@playwright/test';

test.describe('Homepage', () => {
  test('loads correctly with domain input form', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/DNS Tool/i);
    await expect(page.locator('#domainForm')).toBeVisible();
    await expect(page.locator('#domain')).toBeVisible();
    await expect(page.locator('#analyzeBtn')).toBeVisible();
  });

  test('validates domain input — rejects invalid domains', async ({ page }) => {
    await page.goto('/');
    const input = page.locator('#domain');
    const btn = page.locator('#analyzeBtn');

    await input.fill('not a valid domain!!!');
    await input.dispatchEvent('input');
    await expect(input).toHaveClass(/is-invalid/);
    await expect(btn).toBeDisabled();
  });

  test('accepts valid domain input', async ({ page }) => {
    await page.goto('/');
    const input = page.locator('#domain');
    const btn = page.locator('#analyzeBtn');

    await input.fill('example.com');
    await input.dispatchEvent('input');
    await expect(input).not.toHaveClass(/is-invalid/);
    await expect(btn).toBeEnabled();
  });

  test('navbar renders with version badge', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('.navbar-brand')).toBeVisible();
    await expect(page.locator('.navbar-brand')).toContainText(/v\d+\.\d+\.\d+/);
  });

  test('advanced options accordion toggles', async ({ page }) => {
    await page.goto('/');
    const toggle = page.locator('button:has-text("Advanced Options")');
    await expect(toggle).toBeVisible();
    await toggle.click();
    await expect(page.locator('#advancedCollapse')).toBeVisible();
  });
});

test.describe('Loading Overlay', () => {
  test('overlay element exists in DOM but is hidden', async ({ page }) => {
    await page.goto('/');
    const overlay = page.locator('#loadingOverlay');
    await expect(overlay).toBeAttached();
    await expect(overlay).not.toHaveClass(/is-active/);
    await expect(overlay).toHaveCSS('opacity', '0');
    await expect(overlay).toHaveCSS('visibility', 'hidden');
  });

  test('overlay does NOT use d-none class (Safari animation fix)', async ({ page }) => {
    await page.goto('/');
    const overlay = page.locator('#loadingOverlay');
    await expect(overlay).toBeAttached();
    await expect(overlay).not.toHaveClass(/d-none/);
    const display = await overlay.evaluate(el => getComputedStyle(el).display);
    expect(display).toBe('flex');
  });

  test('overlay activates on form submit', async ({ page }) => {
    await page.goto('/');
    const input = page.locator('#domain');
    const btn = page.locator('#analyzeBtn');

    await input.fill('example.com');

    await page.evaluate(() => {
      (window as any).__overlayActivated = false;
      const overlay = document.getElementById('loadingOverlay');
      if (overlay) {
        const observer = new MutationObserver((mutations) => {
          for (const m of mutations) {
            if (overlay.classList.contains('is-active')) {
              (window as any).__overlayActivated = true;
            }
          }
        });
        observer.observe(overlay, { attributes: true, attributeFilter: ['class'] });
      }
    });

    await btn.click();

    const activated = await Promise.race([
      page.waitForFunction(() => (window as any).__overlayActivated === true, null, { timeout: 5000 }).then(() => true),
      page.waitForURL('**/analyze**', { timeout: 90000 }).then(() => 'navigated'),
    ]);

    expect(['navigated', true]).toContain(activated);
  });

  test('overlay contains expected elements', async ({ page }) => {
    await page.goto('/');
    const overlay = page.locator('#loadingOverlay');
    await expect(overlay.locator('.loading-spinner')).toBeAttached();
    await expect(overlay.locator('#loadingDomain')).toBeAttached();
    await expect(overlay.locator('#loadingTimer')).toBeAttached();
    await expect(overlay.locator('.loading-dots')).toBeAttached();
    await expect(overlay.locator('.scan-checklist')).toBeAttached();

    const phases = overlay.locator('.scan-phase');
    const count = await phases.count();
    expect(count).toBeGreaterThanOrEqual(6);
  });
});
