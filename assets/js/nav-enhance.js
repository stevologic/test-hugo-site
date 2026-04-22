/*
 * Navbar enhancement — Agentic Remediation Recipes.
 *
 * By default, Hextra renders top-level menu entries that have children
 * (`params.type: menu`) as buttons that toggle a dropdown on click but do
 * not themselves navigate anywhere. That makes the section landing pages
 * harder to reach than they should be — users have to open the dropdown
 * and then click through to the section's own index.
 *
 * This script lights up those dropdowns so that:
 *   - A primary click on the label navigates to the section's landing page.
 *   - Modifier-key / middle-click behave like links (open in new tab).
 *   - On pointer-fine devices (desktop), hovering the trigger opens the
 *     dropdown via a synthetic click, reusing Hextra's own toggle logic —
 *     so no DOM-class guesswork is needed.
 *   - On touch devices, the default tap-to-toggle behaviour is preserved
 *     (we do not attach hover listeners there).
 *
 * The base URL is injected by head-end.html as window.HUGO_BASE_URL so the
 * correct origin + path prefix is used on both local builds and GitHub
 * Pages deploys under a /<repo>/ subpath.
 */
(function () {
  'use strict';

  // Label text → landing-page slug. Must match the top-level menu
  // identifiers in hugo.yaml (weights 2, 4, 5, 7).
  var ROUTES = {
    'Fundamentals':         'fundamentals',
    'Agents':               'agents',
    'Prompt Library':       'prompt-library',
    'Security Remediation': 'security-remediation'
  };

  function baseURL() {
    var raw = window.HUGO_BASE_URL || window.location.origin;
    return String(raw).replace(/\/+$/, '');
  }

  // Strip Hextra's caret/chevron SVG out of the button text so the match
  // works whether or not a <svg> is rendered alongside the label.
  function cleanLabel(btn) {
    var text = btn.textContent || '';
    return text.replace(/\s+/g, ' ').trim();
  }

  function routeFor(label) {
    for (var key in ROUTES) {
      if (!Object.prototype.hasOwnProperty.call(ROUTES, key)) continue;
      if (label === key) return ROUTES[key];
      // Tolerate trailing caret text, pluralisation, or suffix noise
      if (label.indexOf(key) === 0) return ROUTES[key];
    }
    return null;
  }

  function setup() {
    // Hextra's navbar container — scope the selector tightly so we don't
    // touch buttons in the page body, mobile sheet, or search widget.
    var nav = document.querySelector('.nextra-nav-container nav');
    if (!nav) return;

    var base = baseURL();
    var hoverCapable = window.matchMedia &&
                       window.matchMedia('(hover: hover) and (pointer: fine)').matches;

    // Shared flag so our click handler can distinguish a real user click
    // (→ navigate) from a synthetic click we dispatch on hover
    // (→ let Hextra's toggle open the panel).
    var suppressNav = false;

    // Only scan direct-ish children of the nav: top-level triggers only.
    // We still use querySelectorAll and filter to keep selector simple.
    nav.querySelectorAll('button').forEach(function (btn) {
      var label = cleanLabel(btn);
      var slug = routeFor(label);
      if (!slug) return;

      var href = base + '/' + slug + '/';

      // --- Click → navigate ---------------------------------------------
      // Capture phase + stopImmediatePropagation so we pre-empt any toggle
      // handler Hextra has bound on the same button.
      btn.addEventListener('click', function (e) {
        if (suppressNav) return;
        if (e.button !== 0) return;
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
          // Let the browser's default handling happen for modifier clicks
          // so open-in-new-tab still works. We need to navigate manually
          // though, because the button has no default href.
          e.preventDefault();
          e.stopImmediatePropagation();
          window.open(href, '_blank', 'noopener');
          return;
        }
        e.preventDefault();
        e.stopImmediatePropagation();
        window.location.assign(href);
      }, true);

      // Middle-click → new tab.
      btn.addEventListener('auxclick', function (e) {
        if (e.button === 1) {
          e.preventDefault();
          window.open(href, '_blank', 'noopener');
        }
      });

      // Keyboard: Enter should navigate (not toggle), consistent with
      // the new "this is a link" affordance.
      btn.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          window.location.assign(href);
        }
      });

      // Visual & a11y affordances: make it look and announce as a link.
      btn.style.cursor = 'pointer';
      btn.setAttribute('role', 'link');
      btn.setAttribute('data-nav-href', href);
      btn.setAttribute('aria-label', label + ' — open section (dropdown on hover)');

      // --- Hover → open dropdown ---------------------------------------
      if (!hoverCapable) return;

      var container = btn.closest('.relative, li') || btn.parentElement;
      if (!container) return;

      var hoverOpen = false;
      var closeTimer = null;

      function clearCloseTimer() {
        if (closeTimer) { clearTimeout(closeTimer); closeTimer = null; }
      }

      container.addEventListener('mouseenter', function () {
        clearCloseTimer();
        if (btn.getAttribute('aria-expanded') === 'true') return;
        hoverOpen = true;
        suppressNav = true;
        try { btn.click(); } finally { suppressNav = false; }
      });

      container.addEventListener('mouseleave', function () {
        if (!hoverOpen) return;
        // Small grace period so diagonal cursor movements into the panel
        // don't accidentally close it.
        clearCloseTimer();
        closeTimer = setTimeout(function () {
          hoverOpen = false;
          if (btn.getAttribute('aria-expanded') === 'true') {
            suppressNav = true;
            try { btn.click(); } finally { suppressNav = false; }
          }
        }, 180);
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setup);
  } else {
    setup();
  }
})();
