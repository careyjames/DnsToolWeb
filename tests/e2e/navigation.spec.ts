import { test, expect } from '@playwright/test';

test.describe('Navigation', () => {
  test('all navbar links are present and clickable', async ({ page }) => {
    await page.goto('/');

    const navLinks = [
      { text: 'Analyze', href: '/' },
      { text: 'IP Intelligence', href: '/investigate' },
      { text: 'Email Header', href: '/email-header' },
      { text: 'History', href: '/history' },
      { text: 'Statistics', href: '/stats' },
      { text: 'Sources', href: '/sources' },
    ];

    for (const link of navLinks) {
      const el = page.locator(`nav a:has-text("${link.text}")`).first();
      await expect(el).toBeVisible();
    }
  });

  test('history page loads', async ({ page }) => {
    await page.goto('/history');
    await expect(page).toHaveTitle(/DNS Tool/i);
    await expect(page.locator('text=/History|Recent/i')).toBeVisible();
  });

  test('IP Intelligence page loads with input form', async ({ page }) => {
    await page.goto('/investigate');
    await expect(page).toHaveTitle(/DNS Tool/i);
  });

  test('sources page loads', async ({ page }) => {
    await page.goto('/sources');
    await expect(page).toHaveTitle(/DNS Tool/i);
  });

  test('stats page loads', async ({ page }) => {
    await page.goto('/stats');
    await expect(page).toHaveTitle(/DNS Tool/i);
  });
});

test.describe('Responsive Layout', () => {
  test('page is usable at mobile width', async ({ page, browserName }) => {
    test.skip(browserName === 'webkit' && !!page.context().browser()?.version(), 'viewport set by device profile');
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/');
    await expect(page.locator('#domainForm')).toBeVisible();
    await expect(page.locator('#domain')).toBeVisible();
  });

  test('page is usable at tablet width', async ({ page, browserName }) => {
    test.skip(browserName === 'webkit' && !!page.context().browser()?.version(), 'viewport set by device profile');
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/');
    await expect(page.locator('#domainForm')).toBeVisible();
  });
});
