(function () {
  const root = window.parent;
  const doc = root.document;

  const asBoolean = (value) => String(value || '').toLowerCase() === 'true';

  // Clean up the previous Inbox scroll-reset experiment if this patch is
  // applied over v2 without a full browser restart. That version installed a
  // document-wide click handler plus a temporary DOM observer/interval, which
  // could compete with unrelated Streamlit rerenders (email selection, To-Do
  // status changes) and leave the app on a blank frame.
  if (root.__mailMindInboxNavigationHandler) {
    doc.removeEventListener(
      'click',
      root.__mailMindInboxNavigationHandler,
      true
    );
    root.__mailMindInboxNavigationHandler = null;
  }
  if (root.__mailMindInboxScrollResetTimer) {
    root.clearInterval(root.__mailMindInboxScrollResetTimer);
    root.__mailMindInboxScrollResetTimer = null;
  }
  if (root.__mailMindInboxScrollResetStopTimer) {
    root.clearTimeout(root.__mailMindInboxScrollResetStopTimer);
    root.__mailMindInboxScrollResetStopTimer = null;
  }
  if (root.__mailMindInboxScrollResetObserver) {
    root.__mailMindInboxScrollResetObserver.disconnect();
    root.__mailMindInboxScrollResetObserver = null;
  }

  const renderLoginDomHelpers = (marker) => {
    const suppressAutofill = asBoolean(marker.dataset.suppressAutofill);
    const hasEmailError = asBoolean(marker.dataset.hasEmailError);
    const hasAuthError = asBoolean(marker.dataset.hasAuthError);

    // Remove every legacy login listener left by older app reruns. Those
    // handlers rewrote DOM values and could submit an older email value.
    if (root.__mailMindEnterHandler) {
      doc.removeEventListener('keydown', root.__mailMindEnterHandler, true);
      root.__mailMindEnterHandler = null;
    }
    if (root.__mailMindClickHandler) {
      doc.removeEventListener('click', root.__mailMindClickHandler, true);
      root.__mailMindClickHandler = null;
    }
    if (root.__mailMindTypingHandler) {
      doc.removeEventListener('keydown', root.__mailMindTypingHandler, true);
      doc.removeEventListener('input', root.__mailMindTypingHandler, true);
      root.__mailMindTypingHandler = null;
    }
    if (root.__mailMindFieldErrorClearHandler) {
      doc.removeEventListener(
        'input',
        root.__mailMindFieldErrorClearHandler,
        true
      );
      root.__mailMindFieldErrorClearHandler = null;
    }
    if (root.__mailMindLoginHelperTimer) {
      root.clearInterval(root.__mailMindLoginHelperTimer);
      root.__mailMindLoginHelperTimer = null;
    }
    root.__mailMindSyntheticLoginClick = false;
    root.__mailMindLastSubmit = 0;

    const getControls = () => ({
      page: doc.querySelector('.st-key-login_page'),
      form: doc.querySelector('.st-key-login_form'),
      emailContainer: doc.querySelector('.st-key-login_email'),
      email: doc.querySelector('.st-key-login_email input'),
      passwordContainer: doc.querySelector('.st-key-login_password'),
      password: doc.querySelector('.st-key-login_password input'),
      button: doc.querySelector(
        '.st-key-login_form [data-testid="stFormSubmitButton"] button, ' +
        '.st-key-login_button button'
      )
    });

    const hideApplyHints = () => {
      doc.querySelectorAll(
        '.st-key-login_email *, .st-key-login_password *'
      ).forEach((element) => {
        const value = (element.textContent || '').trim();
        if (value === 'Press Enter to apply') {
          element.classList.add('mailmind-hidden-hint');
          element.setAttribute('aria-hidden', 'true');
        }
      });
    };

    const applyAttributes = () => {
      const {
        page, emailContainer, email, passwordContainer, password, button
      } = getControls();
      if (!page) return false;

      // Keep accessibility state in sync with the server-rendered error.
      // Visual error styling is handled entirely by CSS :has(...) selectors,
      // so it survives Streamlit DOM replacement and repeated identical errors.
      if (email) {
        email.setAttribute('aria-invalid', hasEmailError ? 'true' : 'false');
      }
      if (password) {
        password.setAttribute('aria-invalid', hasAuthError ? 'true' : 'false');
      }

      if (email) {
        email.setAttribute('autocapitalize', 'off');
        email.setAttribute('autocorrect', 'off');
        email.setAttribute('spellcheck', 'false');
        email.setAttribute('autocomplete', 'off');
        email.setAttribute('name', 'mailmind_email_input');
        email.setAttribute('data-lpignore', 'true');
        email.setAttribute('data-1p-ignore', 'true');
        email.setAttribute('data-form-type', 'other');
      }

      if (password) {
        password.setAttribute('autocapitalize', 'off');
        password.setAttribute('autocorrect', 'off');
        password.setAttribute('spellcheck', 'false');
        password.setAttribute(
          'autocomplete',
          suppressAutofill ? 'new-password' : 'current-password'
        );
        password.setAttribute('name', 'mailmind_password_input');
        password.setAttribute('data-lpignore', 'true');
        password.setAttribute('data-1p-ignore', 'true');
        password.setAttribute('data-form-type', 'other');
      }

      hideApplyHints();
      return true;
    };

    // Submit with Enter anywhere on the login page, including while
    // the cursor is inside either field. Prevent Streamlit's first
    // "apply" Enter from swallowing the login submission, then click
    // the real form submit button once.
    const handleOutsideEnter = (event) => {
      if (
        !event.isTrusted ||
        event.key !== 'Enter' ||
        event.repeat ||
        event.isComposing ||
        event.shiftKey ||
        event.ctrlKey ||
        event.altKey ||
        event.metaKey
      ) return;

      const { page, email, password, button } = getControls();
      if (!page || !button || button.disabled) return;

      const now = Date.now();
      if (now - root.__mailMindLastSubmit < 700) return;
      root.__mailMindLastSubmit = now;

      event.preventDefault();
      event.stopPropagation();
      if (typeof event.stopImmediatePropagation === 'function') {
        event.stopImmediatePropagation();
      }

      // Blur only to finish any active edit. The values themselves are
      // never rewritten, so validation always receives what is visible.
      if (event.target === email || event.target === password) {
        event.target.blur();
      }

      root.requestAnimationFrame(() => {
        root.requestAnimationFrame(() => button.click());
      });
    };

    if (root.__mailMindStableEnterHandler) {
      doc.removeEventListener(
        'keydown',
        root.__mailMindStableEnterHandler,
        true
      );
    }
    root.__mailMindStableEnterHandler = handleOutsideEnter;
    doc.addEventListener(
      'keydown',
      root.__mailMindStableEnterHandler,
      true
    );

    // Keep server-side errors visible until the next explicit submit.
    // Browser autofill and Streamlit's value restoration can emit synthetic
    // input events; hiding errors on those events caused intermittent errors
    // that only appeared after a manual refresh.

    applyAttributes();
    let attempts = 0;
    root.__mailMindLoginHelperTimer = root.setInterval(() => {
      applyAttributes();
      attempts += 1;
      if (attempts > 30) {
        root.clearInterval(root.__mailMindLoginHelperTimer);
        root.__mailMindLoginHelperTimer = null;
      }
    }, 200);
  };

  const renderMicrosoftRedirect = (marker) => {
    const url = marker.dataset.url || '';
    if (!url) return;

    const markerName = '__mailMindMicrosoftSameTabRedirect';
    const anchorId = 'mailmind-microsoft-same-tab-redirect';

    // If the browser restores this page from its back/forward cache,
    // reload MailMind once. The server-side redirect flag was already
    // consumed, so the reload shows the regular login form instead of
    // redirecting to Microsoft again.
    if (root.__mailMindMicrosoftBackHandler) {
      root.removeEventListener(
        'pageshow',
        root.__mailMindMicrosoftBackHandler
      );
    }
    root.__mailMindMicrosoftBackHandler = (event) => {
      if (!event.persisted) return;
      root[markerName] = null;
      root.location.reload();
    };
    root.addEventListener(
      'pageshow',
      root.__mailMindMicrosoftBackHandler
    );

    // Prevent repeated Streamlit reruns from navigating more than once
    // while the current page is leaving localhost.
    if (root[markerName] === url) return;
    root[markerName] = url;

    let anchor = doc.getElementById(anchorId);
    if (!anchor) {
      anchor = doc.createElement('a');
      anchor.id = anchorId;
      anchor.hidden = true;
      anchor.setAttribute('aria-hidden', 'true');
      doc.body.appendChild(anchor);
    }

    anchor.href = url;
    anchor.target = '_self';
    anchor.rel = 'noopener';

    // The explicit _self target keeps OAuth in the current tab.
    root.requestAnimationFrame(() => anchor.click());
  };



  const listSelectors = {
    inbox: '[class*="st-key-inbox_list_scroll_"]',
    summary: '[class*="st-key-summary_list_scroll_"]',
    todo: '[class*="st-key-todo_task_list_"]'
  };

  const scrollSurfaceToTop = (target) => {
    const selector = listSelectors[target];
    if (!selector) return;

    doc.querySelectorAll(selector).forEach((surface) => {
      const candidates = [
        surface,
        ...surface.querySelectorAll('[data-testid="stVerticalBlockBorderWrapper"]')
      ];
      candidates.forEach((candidate) => {
        try {
          const style = root.getComputedStyle(candidate);
          const isScrollable =
            candidate.scrollHeight > candidate.clientHeight + 2 ||
            style.overflowY === 'auto' ||
            style.overflowY === 'scroll';
          if (isScrollable) candidate.scrollTop = 0;
        } catch (_) {
          // A Streamlit rerun can replace the node between query and write.
          // The short retry below will resolve the replacement surface.
        }
      });
    });
  };

  const scheduleScrollReset = (target) => {
    if (!listSelectors[target]) return;
    root.__mailMindScrollResetTimers = root.__mailMindScrollResetTimers || {};
    const timers = root.__mailMindScrollResetTimers;
    (timers[target] || []).forEach((timer) => root.clearTimeout(timer));

    // Reset immediately so a newly-rendered page never intentionally inherits
    // the old page's scroll position. Then use a few bounded retries while
    // Streamlit/React finishes the same render. No interval, click interception,
    // list re-key, or long-lived DOM polling is involved.
    scrollSurfaceToTop(target);
    root.requestAnimationFrame(() => scrollSurfaceToTop(target));
    root.requestAnimationFrame(() => {
      root.requestAnimationFrame(() => scrollSurfaceToTop(target));
    });
    timers[target] = [45, 120, 260].map((delay) =>
      root.setTimeout(() => scrollSurfaceToTop(target), delay)
    );
  };

  const renderScrollReset = (marker) => {
    const target = String(marker.dataset.mailmindScrollTarget || '').toLowerCase();
    if (!listSelectors[target]) return;
    scheduleScrollReset(target);
  };

  const scrollReaderToLatestTurn = (marker) => {
    const viewportKey = String(marker.dataset.mailmindReaderScrollLatest || '').trim();
    if (!viewportKey) return;

    let viewport = null;
    try {
      const escapedKey = root.CSS && typeof root.CSS.escape === 'function'
        ? root.CSS.escape(viewportKey)
        : viewportKey.replace(/[^a-zA-Z0-9_-]/g, '\\$&');
      viewport = doc.querySelector(`.st-key-${escapedKey}`);
    } catch (_) {
      viewport = null;
    }
    if (!viewport) return;

    const expanders = viewport.querySelectorAll('[data-testid="stExpander"]');
    const latestExpander = expanders.length ? expanders[expanders.length - 1] : null;

    try {
      if (latestExpander) {
        // Keep the latest reply header at the top of the reader viewport. This is
        // preferable to scrollTop=scrollHeight because an expanded long reply
        // would otherwise open at its tail instead of its beginning.
        const viewportRect = viewport.getBoundingClientRect();
        const targetRect = latestExpander.getBoundingClientRect();
        viewport.scrollTop += targetRect.top - viewportRect.top - 4;
      } else {
        viewport.scrollTop = viewport.scrollHeight;
      }
    } catch (_) {
      // Streamlit may replace the reader node during the same rerun; bounded
      // retries below will target the replacement DOM.
    }
  };

  const scheduleReaderScrollLatest = (marker) => {
    const viewportKey = String(marker.dataset.mailmindReaderScrollLatest || '').trim();
    if (!viewportKey) return;

    root.__mailMindReaderLatestTimers = root.__mailMindReaderLatestTimers || {};
    const timers = root.__mailMindReaderLatestTimers;
    (timers[viewportKey] || []).forEach((timer) => root.clearTimeout(timer));

    scrollReaderToLatestTurn(marker);
    root.requestAnimationFrame(() => scrollReaderToLatestTurn(marker));
    root.requestAnimationFrame(() => {
      root.requestAnimationFrame(() => scrollReaderToLatestTurn(marker));
    });
    timers[viewportKey] = [45, 120, 260, 480].map((delay) =>
      root.setTimeout(() => scrollReaderToLatestTurn(marker), delay)
    );
  };

  const processMarkers = () => {
    doc.querySelectorAll('template[data-mailmind-login-helper]').forEach((marker) => {
      if (marker.dataset.mailmindProcessed === 'true') return;
      marker.dataset.mailmindProcessed = 'true';
      renderLoginDomHelpers(marker);
    });

    doc.querySelectorAll('template[data-mailmind-microsoft-redirect]').forEach((marker) => {
      if (marker.dataset.mailmindProcessed === 'true') return;
      marker.dataset.mailmindProcessed = 'true';
      renderMicrosoftRedirect(marker);
    });

    doc.querySelectorAll('template[data-mailmind-scroll-target]').forEach((marker) => {
      const target = String(marker.dataset.mailmindScrollTarget || '').toLowerCase();
      const request = String(marker.dataset.mailmindScrollRequest || 'legacy');
      if (!listSelectors[target]) return;

      // Do not mutate React-owned marker nodes. Track the last request outside
      // the DOM instead, so identical Streamlit element positions can safely be
      // reused while every pagination/filter request still runs exactly once.
      root.__mailMindLastScrollRequests = root.__mailMindLastScrollRequests || {};
      if (root.__mailMindLastScrollRequests[target] === request) return;
      root.__mailMindLastScrollRequests[target] = request;
      renderScrollReset(marker);
    });

    doc.querySelectorAll('template[data-mailmind-reader-scroll-latest]').forEach((marker) => {
      const viewportKey = String(marker.dataset.mailmindReaderScrollLatest || '').trim();
      const request = String(marker.dataset.mailmindScrollRequest || 'legacy');
      if (!viewportKey) return;

      root.__mailMindLastReaderScrollRequests =
        root.__mailMindLastReaderScrollRequests || {};
      if (root.__mailMindLastReaderScrollRequests[viewportKey] === request) return;
      root.__mailMindLastReaderScrollRequests[viewportKey] = request;
      scheduleReaderScrollLatest(marker);
    });
  };

  // main.js is injected on each full Streamlit rerun, but the document only
  // needs one MutationObserver. Keep it install-once, but do NOT schedule a
  // document scan for every React childList mutation. Workspace swaps can add
  // hundreds of nodes (especially To-Do); scanning on every batch makes the
  // parent document compete with Streamlit while it is replacing the workspace
  // and can leave a visually white/stale frame even though the server run has
  // already completed. Only marker insertions are relevant to this helper.
  const observerVersion = 'mailmind-marker-only-observer-v5';
  const markerSelector = [
    'template[data-mailmind-login-helper]',
    'template[data-mailmind-microsoft-redirect]',
    'template[data-mailmind-scroll-target]',
    'template[data-mailmind-reader-scroll-latest]'
  ].join(',');

  if (
    root.__mailMindMainJsObserver &&
    root.__mailMindMainJsObserverVersion !== observerVersion
  ) {
    root.__mailMindMainJsObserver.disconnect();
    root.__mailMindMainJsObserver = null;
  }
  root.__mailMindMainJsObserverVersion = observerVersion;
  root.__mailMindProcessMarkers = processMarkers;

  // Rebind the scheduler on a version upgrade so no queued callback from the
  // old observer keeps running against a workspace that is already being
  // replaced. One requestAnimationFrame is enough to coalesce real markers.
  if (!root.__mailMindScheduleMarkerScan || root.__mailMindMarkerSchedulerVersion !== observerVersion) {
    root.__mailMindMarkerScanQueued = false;
    root.__mailMindMarkerSchedulerVersion = observerVersion;
    root.__mailMindScheduleMarkerScan = () => {
      if (root.__mailMindMarkerScanQueued) return;
      root.__mailMindMarkerScanQueued = true;
      root.requestAnimationFrame(() => {
        root.__mailMindMarkerScanQueued = false;
        if (typeof root.__mailMindProcessMarkers === 'function') {
          root.__mailMindProcessMarkers();
        }
      });
    };
  }

  const nodeContainsMailMindMarker = (node) => {
    if (!node || node.nodeType !== 1) return false;
    try {
      if (typeof node.matches === 'function' && node.matches(markerSelector)) {
        return true;
      }
      return Boolean(
        typeof node.querySelector === 'function' && node.querySelector(markerSelector)
      );
    } catch (_) {
      return false;
    }
  };

  if (!root.__mailMindMainJsObserver) {
    root.__mailMindMainJsObserver = new root.MutationObserver((mutations) => {
      const hasRelevantMarker = mutations.some((mutation) =>
        Array.from(mutation.addedNodes || []).some(nodeContainsMailMindMarker)
      );
      if (!hasRelevantMarker) return;
      root.__mailMindScheduleMarkerScan();
    });
    root.__mailMindMainJsObserver.observe(doc.documentElement, {
      childList: true,
      subtree: true
    });
  }


  // Reader height is intentionally NOT managed by JavaScript. The Email
  // Content outer pane is the single vertical scroll authority; setting an
  // inline max-height on the inner reader recreates a second scrollbar.
  if (root.__mailMindReaderResizeHandler) {
    root.removeEventListener('resize', root.__mailMindReaderResizeHandler);
    root.__mailMindReaderResizeHandler = null;
  }

  root.__mailMindScheduleMarkerScan();
  root.__mailMindProcessMarkers();
})();
