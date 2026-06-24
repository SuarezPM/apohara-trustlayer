/* VOUCH demo UI — vanilla JS, no framework.
 *
 * Three panels:
 *   1. Live transcript (SSE stream from /events)
 *   2. Cost panel (live spend, AIML + Featherless)
 *   3. EU AI Act Art. 12 dashboard (8 fields, >=7/8 compliant)
 *
 * Hallmark: no emoji, no frameworks, single file, no globals.
 */

(function () {
  'use strict';

  // -------- EU AI Act Art. 12 fields (canonical 8) --------
  const ART12_FIELDS = [
    'start_time',
    'end_time',
    'reference_database',
    'input_data',
    'natural_person_id',
    'decision_id',
    'policy_version',
    'hash_chain_prev',
  ];

  // -------- helpers --------
  function $(sel) { return document.querySelector(sel); }
  function el(tag, props, children) {
    const e = document.createElement(tag);
    if (props) Object.assign(e, props);
    if (children) children.forEach(c => c && e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
    return e;
  }
  function fmtUsd(n) {
    if (!Number.isFinite(n)) return '$0.000000';
    return '$' + n.toFixed(6);
  }
  function fmtTokens(in_, out_) {
    return (in_ || 0).toLocaleString() + ' / ' + (out_ || 0).toLocaleString();
  }
  function shortTs(iso) {
    // "2026-06-18T12:34:56Z" -> "12:34:56"
    const m = /T(\d{2}:\d{2}:\d{2})/.exec(iso || '');
    return m ? m[1] : '--:--:--';
  }

  // -------- state --------
  const state = {
    caseId: null,
    totalUsd: 0.0,
    byAgent: new Map(), // agent -> { provider, model, tokens_in, tokens_out, cost_usd }
    transcript: [],
    art12: new Map(ART12_FIELDS.map(f => [f, false])),
    halted: false,
  };

  // -------- DOM refs --------
  const transcriptEl = $('#transcript');
  const transcriptMeta = $('#transcript-meta');
  const costTotal = $('#cost-total');
  const costRows = $('#cost-rows');
  const complianceEl = $('#compliance');
  const coverageBadge = $('#coverage-badge');
  const haltFlag = $('#halt-flag');
  const haltModal = $('#halt-modal');
  const haltModalReason = $('#halt-modal-reason');
  const haltModalClose = $('#halt-modal-close');
  const caseInput = $('#case-input');
  const caseLoadBtn = $('#case-load');
  const caseIdLabel = $('#case-id');
  const downloadLink = $('#download-pdf');

  // -------- compliance panel render --------
  function renderCompliance() {
    complianceEl.innerHTML = '';
    let populated = 0;
    ART12_FIELDS.forEach(name => {
      const ok = !!state.art12.get(name);
      if (ok) populated += 1;
      const li = el('li', null, [
        el('span', { className: 'name', textContent: name }),
        el('span', {
          className: 'mark ' + (ok ? 'mark--ok' : 'mark--missing'),
          textContent: ok ? 'PASS' : 'MISSING',
        }),
      ]);
      complianceEl.appendChild(li);
    });
    coverageBadge.textContent = populated + '/8 fields populated';
    coverageBadge.style.color = populated >= 7 ? 'var(--approve)' : 'var(--halt)';
  }

  // Initial render: all missing.
  renderCompliance();

  // -------- cost panel render --------
  function renderCostPanel() {
    costTotal.textContent = fmtUsd(state.totalUsd);
    costRows.innerHTML = '';
    const sorted = Array.from(state.byAgent.entries()).sort((a, b) =>
      b[1].cost_usd - a[1].cost_usd,
    );
    sorted.forEach(([agent, agg]) => {
      const tr = el('tr', null, [
        el('td', { textContent: agent }),
        el('td', { textContent: agg.provider }),
        el('td', { textContent: agg.model }),
        el('td', { className: 'num', textContent: fmtTokens(agg.tokens_in, agg.tokens_out) }),
        el('td', { className: 'num', textContent: fmtUsd(agg.cost_usd) }),
      ]);
      costRows.appendChild(tr);
    });
  }

  // -------- transcript render --------
  function pushTranscript(row) {
    state.transcript.push(row);
    if (state.transcript.length > 500) state.transcript.shift();
    transcriptMeta.textContent = state.transcript.length + ' events';
    const li = el('li', null, [
      el('span', { className: 'ts', textContent: shortTs(row.timestamp) }),
      el('span', { className: 'agent', textContent: row.agent }),
      el('span', { className: 'msg', textContent: row.provider + '/' + row.model + ' (' + row.tokens_in + ' in / ' + row.tokens_out + ' out)' }),
    ]);
    transcriptEl.appendChild(li);
    transcriptEl.scrollTop = transcriptEl.scrollHeight;
  }

  // -------- event ingest --------
  function ingest(row) {
    if (!row || !row.agent) return;
    state.totalUsd += row.cost_usd || 0;
    const prev = state.byAgent.get(row.agent) || {
      provider: row.provider,
      model: row.model,
      tokens_in: 0,
      tokens_out: 0,
      cost_usd: 0,
    };
    prev.tokens_in += row.tokens_in;
    prev.tokens_out += row.tokens_out;
    prev.cost_usd += row.cost_usd;
    state.byAgent.set(row.agent, prev);
    pushTranscript(row);
    renderCostPanel();
  }

  // -------- SSE stream --------
  function connectSSE() {
    const es = new EventSource('/events');
    es.addEventListener('cost-log', function (ev) {
      try {
        const payload = JSON.parse(ev.data);
        if (payload && payload.row) {
          ingest(payload.row);
        }
      } catch (e) {
        console.warn('cost-log parse error', e);
      }
    });
    es.addEventListener('halt', function (ev) {
      try {
        const payload = JSON.parse(ev.data);
        triggerHalt(payload && payload.reason ? payload.reason : 'risk detected');
      } catch (e) {
        triggerHalt('risk detected');
      }
    });
    es.onerror = function () {
      // Browser auto-reconnects; nothing to do.
      console.warn('SSE connection dropped, browser will retry');
    };
    return es;
  }

  // -------- HALT --------
  function triggerHalt(reason) {
    if (state.halted) return;
    state.halted = true;
    haltFlag.textContent = 'HALTED';
    haltFlag.classList.remove('status-pill--ok');
    haltFlag.classList.add('status-pill--halt');
    haltModalReason.textContent = reason;
    haltModal.hidden = false;
    document.body.classList.add('is-halted');
  }
  haltModalClose.addEventListener('click', function () {
    haltModal.hidden = true;
  });

  // -------- case load --------
  function loadCase(caseId) {
    state.caseId = caseId;
    caseIdLabel.textContent = 'case: ' + caseId;
    downloadLink.href = '/evidence/' + encodeURIComponent(caseId);
    // Simulate Art. 12 compliance for a loaded case (real production
    // wires this to the orchestrator's response payload — the demo
    // UI just shows the regulator what "compliant" looks like).
    ART12_FIELDS.forEach(f => state.art12.set(f, true));
    renderCompliance();
  }
  caseLoadBtn.addEventListener('click', function () {
    const v = (caseInput.value || '').trim();
    if (v) loadCase(v);
  });
  caseInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') {
      const v = (caseInput.value || '').trim();
      if (v) loadCase(v);
    }
  });

  // -------- boot --------
  document.addEventListener('DOMContentLoaded', function () {
    connectSSE();
  });
})();