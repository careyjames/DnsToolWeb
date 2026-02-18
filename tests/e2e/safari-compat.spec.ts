import { test, expect } from '@playwright/test';

test.describe('Safari/WebKit Compatibility', () => {
  test('loading overlay uses opacity-based hiding (not display:none)', async ({ page }) => {
    await page.goto('/');
    const overlay = page.locator('#loadingOverlay');
    await expect(overlay).toBeAttached();

    const styles = await overlay.evaluate(el => {
      const cs = getComputedStyle(el);
      return {
        display: cs.display,
        opacity: cs.opacity,
        visibility: cs.visibility,
        pointerEvents: cs.pointerEvents,
      };
    });

    expect(styles.display).toBe('flex');
    expect(styles.opacity).toBe('0');
    expect(styles.visibility).toBe('hidden');
    expect(styles.pointerEvents).toBe('none');
  });

  test('overlay element is div with role=status (not output tag)', async ({ page }) => {
    await page.goto('/');
    const overlay = page.locator('#loadingOverlay');
    const tagName = await overlay.evaluate(el => el.tagName.toLowerCase());
    expect(tagName).toBe('div');
    const role = await overlay.getAttribute('role');
    expect(role).toBe('status');
  });

  test('no inline onclick/onchange handlers (CSP compliance)', async ({ page }) => {
    await page.goto('/');
    const inlineHandlers = await page.evaluate(() => {
      const allElements = document.querySelectorAll('*');
      const violations: string[] = [];
      allElements.forEach(el => {
        const attrs = el.attributes;
        for (let i = 0; i < attrs.length; i++) {
          const name = attrs[i].name.toLowerCase();
          if (name.startsWith('on') && name !== 'one') {
            violations.push(`${el.tagName}#${el.id || '(no-id)'} has ${name}`);
          }
        }
      });
      return violations;
    });
    expect(inlineHandlers).toEqual([]);
  });

  test('CSS animations are defined (not suppressed by display:none)', async ({ page }) => {
    await page.goto('/');
    const pulseExists = await page.evaluate(() => {
      const sheets = document.styleSheets;
      for (let i = 0; i < sheets.length; i++) {
        try {
          const rules = sheets[i].cssRules;
          for (let j = 0; j < rules.length; j++) {
            if (rules[j] instanceof CSSKeyframesRule && (rules[j] as CSSKeyframesRule).name === 'pulse') {
              return true;
            }
          }
        } catch (e) {}
      }
      return false;
    });
    expect(pulseExists).toBe(true);
  });

  test('loading dots animation keyframes exist', async ({ page }) => {
    await page.goto('/');
    const bounceExists = await page.evaluate(() => {
      const sheets = document.styleSheets;
      for (let i = 0; i < sheets.length; i++) {
        try {
          const rules = sheets[i].cssRules;
          for (let j = 0; j < rules.length; j++) {
            if (rules[j] instanceof CSSKeyframesRule && (rules[j] as CSSKeyframesRule).name === 'bounce') {
              return true;
            }
          }
        } catch (e) {}
      }
      return false;
    });
    expect(bounceExists).toBe(true);
  });

  test('history page overlay uses same pattern', async ({ page }) => {
    await page.goto('/history');
    const overlay = page.locator('#loadingOverlay');
    if (await overlay.count() > 0) {
      const styles = await overlay.evaluate(el => {
        const cs = getComputedStyle(el);
        return { display: cs.display, opacity: cs.opacity, visibility: cs.visibility };
      });
      expect(styles.display).toBe('flex');
      expect(styles.opacity).toBe('0');
      expect(styles.visibility).toBe('hidden');

      const tagName = await overlay.evaluate(el => el.tagName.toLowerCase());
      expect(tagName).toBe('div');
    }
  });

  test('investigate page overlay uses same pattern', async ({ page }) => {
    await page.goto('/investigate');
    const overlay = page.locator('#loadingOverlay');
    if (await overlay.count() > 0) {
      const styles = await overlay.evaluate(el => {
        const cs = getComputedStyle(el);
        return { display: cs.display, opacity: cs.opacity, visibility: cs.visibility };
      });
      expect(styles.display).toBe('flex');
      expect(styles.opacity).toBe('0');
      expect(styles.visibility).toBe('hidden');

      const tagName = await overlay.evaluate(el => el.tagName.toLowerCase());
      expect(tagName).toBe('div');
    }
  });
});
