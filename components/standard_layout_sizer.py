"""Standard mode layout sizer — injects JavaScript to equalize chat/history scroll heights."""

import streamlit.components.v1 as components

# Inline JS runs in parent frame — finds Standard mode panels and sets flex + overflow.
_SIZER_HTML = """
<script>
(function () {
  const doc = window.parent.document;
  const win = window.parent;
  let rafId = null;
  let debounceId = null;

  function findPanel(markerClass) {
    const marker = doc.querySelector("." + markerClass);
    if (!marker) return null;

    const layoutWrapper = marker.closest('[data-testid="stLayoutWrapper"]');
    if (layoutWrapper) {
      const panel = layoutWrapper.querySelector(':scope > [data-testid="stVerticalBlock"]');
      if (panel) return panel;
    }

    return marker.closest('[data-testid="stVerticalBlockBorderWrapper"]') || null;
  }

  function findScrollBlock(panel, markerClass) {
    const marker = panel.querySelector("." + markerClass);
    if (!marker) return null;

    const layoutWrapper = marker.closest('[data-testid="stLayoutWrapper"]');
    if (layoutWrapper) {
      const scrollBlock = layoutWrapper.querySelector(':scope > [data-testid="stVerticalBlock"]');
      if (scrollBlock) return scrollBlock;
    }

    let block = null;
    panel.querySelectorAll('[data-testid="stVerticalBlockBorderWrapper"]').forEach(function (box) {
      if (box !== panel && box.contains(marker)) {
        block = box;
      }
    });
    if (block) return block;

    const panelBody = panel.querySelector(':scope > div > [data-testid="stVerticalBlock"]') || panel;
    panel.querySelectorAll('[data-testid="stVerticalBlock"]').forEach(function (vb) {
      if (vb !== panelBody && vb.contains(marker)) {
        block = vb;
      }
    });
    return block;
  }

  function findChatRow() {
    const chatRow = doc.querySelector('[data-testid="stHorizontalBlock"]:has(.standard-history-panel)');
    if (!chatRow) return { chatRow: null, chatRowWrapper: null };
    const chatRowWrapper = chatRow.closest('[data-testid="stLayoutWrapper"]');
    return { chatRow, chatRowWrapper };
  }

  function findChatInputBlock() {
    const marker = doc.querySelector(".standard-chat-input-row");
    if (!marker) return null;

    const form = marker.closest('[data-testid="stForm"]');
    if (form) return form;

    const layoutWrapper = marker.closest('[data-testid="stLayoutWrapper"]');
    if (layoutWrapper) return layoutWrapper;

    return marker.closest('[data-testid="stElementContainer"]');
  }

  function alignIncidentSpacer(historyPanel, chatPanel, historyScroll, chatScroll) {
    const spacer = historyPanel.querySelector(".standard-history-incident-spacer");
    if (!spacer || !chatPanel.querySelector(".standard-chat-incident-header")) {
      if (spacer) {
        spacer.style.setProperty("height", "0px", "important");
        spacer.style.setProperty("flex", "0 0 0px", "important");
      }
      return;
    }

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const delta = chatScroll.getBoundingClientRect().top - historyScroll.getBoundingClientRect().top;
      if (Math.abs(delta) < 2) break;
      const nextHeight = Math.max(0, Math.round(spacer.getBoundingClientRect().height + delta));
      spacer.style.setProperty("height", nextHeight + "px", "important");
      spacer.style.setProperty("flex", "0 0 " + nextHeight + "px", "important");
    }
  }

  function sizeScrollAreas() {
    if (!doc.querySelector(".standard-mode-root")) return;

    const { chatRow, chatRowWrapper } = findChatRow();
    if (!chatRow) return;

    const rowRect = (chatRowWrapper || chatRow).getBoundingClientRect();
    if (rowRect.height < 40) return;

    const historyPanel = findPanel("standard-history-panel");
    const chatPanel = findPanel("standard-chat-panel");
    if (!historyPanel || !chatPanel) return;

    if (chatRowWrapper) {
      chatRowWrapper.style.setProperty("flex", "1 1 0%", "important");
      chatRowWrapper.style.setProperty("min-height", "0", "important");
      chatRowWrapper.style.setProperty("max-height", "100%", "important");
      chatRowWrapper.style.setProperty("overflow", "hidden", "important");
      chatRowWrapper.style.setProperty("display", "flex", "important");
      chatRowWrapper.style.setProperty("flex-direction", "column", "important");
    }

    chatRow.style.setProperty("flex", "1 1 0%", "important");
    chatRow.style.setProperty("min-height", "0", "important");
    chatRow.style.setProperty("max-height", "100%", "important");
    chatRow.style.setProperty("overflow", "hidden", "important");
    chatRow.style.setProperty("align-items", "stretch", "important");

    chatRow.querySelectorAll('[data-testid="stColumn"]').forEach(function (column) {
      column.style.setProperty("display", "flex", "important");
      column.style.setProperty("flex-direction", "column", "important");
      column.style.setProperty("min-height", "0", "important");
      column.style.setProperty("height", "100%", "important");
      column.style.setProperty("max-height", "100%", "important");
      column.style.setProperty("overflow", "hidden", "important");
    });

    [historyPanel, chatPanel].forEach(function (panel) {
      panel.style.setProperty("height", "100%", "important");
      panel.style.setProperty("max-height", "100%", "important");
      panel.style.setProperty("min-height", "0", "important");
      panel.style.setProperty("overflow", "hidden", "important");
      panel.style.setProperty("flex", "1 1 0%", "important");
    });

    const historyScroll = findScrollBlock(historyPanel, "standard-history-scroll-box");
    const chatScroll = findScrollBlock(chatPanel, "standard-chat-scroll-box");
    if (!historyScroll || !chatScroll) return;

    alignIncidentSpacer(historyPanel, chatPanel, historyScroll, chatScroll);

    const chatInputBlock = findChatInputBlock();
    const historyBottom = historyPanel.getBoundingClientRect().bottom - 6;
    const historyHeight = Math.floor(historyBottom - historyScroll.getBoundingClientRect().top);

    const chatBottom = chatInputBlock
      ? chatInputBlock.getBoundingClientRect().top - 4
      : historyBottom;
    const chatHeight = Math.floor(chatBottom - chatScroll.getBoundingClientRect().top);

    const safeHistoryHeight = Math.max(120, historyHeight);
    const safeChatHeight = Math.max(120, chatHeight);

    [historyScroll].forEach(function (scrollBlock) {
      scrollBlock.style.setProperty("height", safeHistoryHeight + "px", "important");
      scrollBlock.style.setProperty("max-height", safeHistoryHeight + "px", "important");
      scrollBlock.style.setProperty("min-height", "0", "important");
      scrollBlock.style.setProperty("flex", "1 1 " + safeHistoryHeight + "px", "important");
      scrollBlock.style.setProperty("overflow-y", "auto", "important");
      scrollBlock.style.setProperty("overflow-x", "hidden", "important");
    });

    [chatScroll].forEach(function (scrollBlock) {
      scrollBlock.style.setProperty("height", safeChatHeight + "px", "important");
      scrollBlock.style.setProperty("max-height", safeChatHeight + "px", "important");
      scrollBlock.style.setProperty("min-height", "0", "important");
      scrollBlock.style.setProperty("flex", "1 1 " + safeChatHeight + "px", "important");
      scrollBlock.style.setProperty("overflow-y", "auto", "important");
      scrollBlock.style.setProperty("overflow-x", "hidden", "important");
    });
  }

  function schedule() {
    if (rafId) win.cancelAnimationFrame(rafId);
    rafId = win.requestAnimationFrame(sizeScrollAreas);
  }

  function debouncedSchedule() {
    clearTimeout(debounceId);
    debounceId = setTimeout(schedule, 50);
  }

  schedule();
  setTimeout(schedule, 80);
  setTimeout(schedule, 250);
  win.addEventListener("resize", schedule);
  new MutationObserver(debouncedSchedule).observe(doc.body, { childList: true, subtree: true });
})();
</script>
"""


def render_standard_layout_sizer():
    """Mount the layout sizer script at the bottom of Standard mode."""
    components.html(_SIZER_HTML, height=0, scrolling=False)
