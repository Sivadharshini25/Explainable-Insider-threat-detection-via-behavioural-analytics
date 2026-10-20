const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const state = {
  cases: [],
  filtered: [],
  selectedCaseId: null,
  activeCase: null,
  activeEvidence: null,
  page: 1,
  pageSize: 10,
  search: '',
  riskFilter: 'all',
  dateFrom: '',
  dateTo: '',
  sort: 'probability-desc',
  activeTab: 'overview',
};

const riskThresholds = { high: 0.9, critical: 0.99 };

const escapeHtml = (value = '') => String(value).replace(/[&<>"']/g, (char) => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}[char]));

const nice = (value) => String(value).replaceAll('_', ' ').replace(/\b\w/g, (char) => char.toUpperCase());

const probabilityValue = (value) => Number(value || 0);

function api(url, options) {
  return fetch(url, options).then(async (response) => {
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Request failed');
    return data;
  });
}

function getRiskBucket(probability) {
  const p = probabilityValue(probability);
  if (p >= riskThresholds.critical) return 'Critical';
  if (p >= riskThresholds.high) return 'High';
  if (p >= 0.8) return 'Elevated';
  return 'Moderate';
}

function formatPercent(value) {
  return `${(probabilityValue(value) * 100).toFixed(2)}%`;
}

function getEvidenceTotal(caseItem) {
  const counts = caseItem?.evidence_counts || {};
  return Object.values(counts).reduce((total, current) => total + Number(current || 0), 0);
}

function valueOrDash(value) {
  return value === undefined || value === null || value === '' ? '—' : value;
}

function renderOverviewMetrics() {
  const cases = state.cases;
  if (!cases.length) {
    $('#overview-metrics').innerHTML = '<div class="metric-card"><small>Total Flagged Cases</small><strong>0</strong><span>Unavailable</span></div>';
    return;
  }

  const total = cases.length;
  const highRisk = cases.filter((caseItem) => probabilityValue(caseItem.probability) >= riskThresholds.high).length;
  const criticalRisk = cases.filter((caseItem) => probabilityValue(caseItem.probability) >= riskThresholds.critical).length;
  const average = cases.reduce((sum, caseItem) => sum + probabilityValue(caseItem.probability), 0) / total;

  const cards = [
    { label: 'Total Flagged Cases', value: total, note: 'Current dataset' },
    { label: 'High-Risk Cases', value: highRisk, note: `≥ ${riskThresholds.high.toFixed(2)}` },
    { label: 'Average Threat Probability', value: formatPercent(average), note: 'Across all flagged cases' },
    { label: 'Critical-Risk Cases', value: criticalRisk, note: `≥ ${riskThresholds.critical.toFixed(2)}` },
  ];

  $('#overview-metrics').innerHTML = cards.map((card) => `
    <article class="metric-card">
      <small>${card.label}</small>
      <strong>${card.value}</strong>
      <span>${card.note}</span>
    </article>
  `).join('');

  $('#status-text').textContent = `${total} cases loaded • High ≥ ${riskThresholds.high.toFixed(2)} • Critical ≥ ${riskThresholds.critical.toFixed(2)}`;
}

function renderRiskDistribution() {
  const counts = [
    { label: 'Critical', count: state.cases.filter((caseItem) => probabilityValue(caseItem.probability) >= riskThresholds.critical).length },
    { label: 'High', count: state.cases.filter((caseItem) => probabilityValue(caseItem.probability) >= riskThresholds.high && probabilityValue(caseItem.probability) < riskThresholds.critical).length },
    { label: 'Elevated', count: state.cases.filter((caseItem) => probabilityValue(caseItem.probability) >= 0.8 && probabilityValue(caseItem.probability) < riskThresholds.high).length },
    { label: 'Moderate', count: state.cases.filter((caseItem) => probabilityValue(caseItem.probability) < 0.8).length },
  ];

  const maxValue = Math.max(...counts.map((item) => item.count), 1);
  $('#risk-distribution').innerHTML = counts.map((bucket) => `
    <div class="distribution-row">
      <div class="distribution-label">${bucket.label}</div>
      <div class="distribution-bar-track"><span class="distribution-bar ${bucket.label.toLowerCase()}" style="width:${(bucket.count / maxValue) * 100}%"></span></div>
      <div class="distribution-count">${bucket.count}</div>
    </div>
  `).join('');
}

function renderProbabilityDistribution() {
  const data = state.cases.map((caseItem) => probabilityValue(caseItem.probability));
  const bins = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
  const counts = bins.slice(0, -1).map((lower, index) => {
    const upper = bins[index + 1];
    const count = data.filter((value) => value >= lower && value < upper).length;
    return { lower, upper, count };
  });

  const maxValue = Math.max(...counts.map((item) => item.count), 1);
  $('#probability-distribution').innerHTML = counts.map((item) => `
    <div class="distribution-row compact-row">
      <div class="distribution-label">${item.lower.toFixed(1)}-${item.upper.toFixed(1)}</div>
      <div class="distribution-bar-track"><span class="distribution-bar teal" style="width:${(item.count / maxValue) * 100}%"></span></div>
      <div class="distribution-count">${item.count}</div>
    </div>
  `).join('');
}

function renderTemporalTrend() {
  const dates = {};
  state.cases.forEach((caseItem) => {
    const dateKey = caseItem.date || null;
    if (!dateKey) return;
    dates[dateKey] = (dates[dateKey] || 0) + 1;
  });

  const entries = Object.entries(dates).sort(([left], [right]) => new Date(left) - new Date(right));
  if (!entries.length) {
    $('#temporal-trend').innerHTML = '<div class="empty-inline">No valid alert dates available.</div>';
    return;
  }

  const maxValue = Math.max(...entries.map(([, count]) => count), 1);
  $('#temporal-trend').innerHTML = entries.map(([date, count]) => `
    <div class="trend-row">
      <span>${date}</span>
      <div class="trend-track"><span class="trend-bar" style="width:${(count / maxValue) * 100}%"></span></div>
      <strong>${count}</strong>
    </div>
  `).join('');
}

function renderTopIndicators() {
  const aggregate = {};
  state.cases.forEach((caseItem) => {
    const shap = Array.isArray(caseItem.shap) ? caseItem.shap : [];
    shap.forEach((feature) => {
      const name = feature.feature || 'Unknown';
      const contribution = Math.abs(Number(feature.contribution || 0));
      aggregate[name] = (aggregate[name] || 0) + contribution;
    });
  });

  const top = Object.entries(aggregate).sort((left, right) => right[1] - left[1]).slice(0, 6);
  if (!top.length) {
    $('#top-indicators').innerHTML = '<div class="empty-inline">No SHAP feature data available for these cases.</div>';
    return;
  }

  const maxValue = Math.max(...top.map(([, value]) => value), 1);
  $('#top-indicators').innerHTML = top.map(([feature, value]) => `
    <div class="indicator-item">
      <div class="indicator-header"><span>${escapeHtml(feature)}</span><strong>${value.toFixed(3)}</strong></div>
      <div class="distribution-bar-track"><span class="distribution-bar orange" style="width:${(value / maxValue) * 100}%"></span></div>
    </div>
  `).join('');
}

function renderAnalytics() {
  renderRiskDistribution();
  renderProbabilityDistribution();
  renderTemporalTrend();
  renderTopIndicators();
}

function getFilteredCases() {
  const searchText = state.search.trim().toLowerCase();
  let results = [...state.cases];

  if (searchText) {
    results = results.filter((caseItem) => `${caseItem.id} ${caseItem.user}`.toLowerCase().includes(searchText));
  }

  if (state.riskFilter !== 'all') {
    results = results.filter((caseItem) => getRiskBucket(caseItem.probability) === state.riskFilter);
  }

  if (state.dateFrom) {
    results = results.filter((caseItem) => (caseItem.date || '') >= state.dateFrom);
  }

  if (state.dateTo) {
    results = results.filter((caseItem) => (caseItem.date || '') <= state.dateTo);
  }

  switch (state.sort) {
    case 'date-desc':
      results.sort((left, right) => new Date(right.date) - new Date(left.date));
      break;
    case 'date-asc':
      results.sort((left, right) => new Date(left.date) - new Date(right.date));
      break;
    case 'probability-asc':
      results.sort((left, right) => probabilityValue(left.probability) - probabilityValue(right.probability));
      break;
    case 'user-asc':
      results.sort((left, right) => String(left.user).localeCompare(String(right.user)));
      break;
    default:
      results.sort((left, right) => probabilityValue(right.probability) - probabilityValue(left.probability));
      break;
  }

  return results;
}

function renderQueue() {
  const filtered = getFilteredCases();
  state.filtered = filtered;

  const pageCount = Math.max(1, Math.ceil(filtered.length / state.pageSize));
  if (state.page > pageCount) state.page = pageCount;

  const start = (state.page - 1) * state.pageSize;
  const pageCases = filtered.slice(start, start + state.pageSize);

  $('#queue-result-count').textContent = `${filtered.length} result${filtered.length === 1 ? '' : 's'}`;

  $('#threat-rows').innerHTML = pageCases.map((caseItem) => {
    const riskBucket = getRiskBucket(caseItem.probability);
    const evidenceTotal = getEvidenceTotal(caseItem);
    const indicator = Array.isArray(caseItem.indicators) && caseItem.indicators.length ? caseItem.indicators[0] : '—';
    const isSelected = Number(state.selectedCaseId) === Number(caseItem.id);
    return `
      <tr class="queue-row ${isSelected ? 'selected' : ''}" data-case-id="${caseItem.id}">
        <td><div class="case-id">#${caseItem.id}</div></td>
        <td><div class="subject-name">${escapeHtml(caseItem.user)}</div></td>
        <td>${caseItem.date || '—'}</td>
        <td><span class="percent-pill">${formatPercent(caseItem.probability)}</span></td>
        <td><span class="risk-pill ${riskBucket.toLowerCase()}">${riskBucket}</span></td>
        <td class="indicator-cell">${escapeHtml(indicator)}</td>
        <td>${evidenceTotal}</td>
      </tr>
    `;
  }).join('') || '<tr><td colspan="7" class="empty-row">No matching cases found.</td></tr>';

  $$('#threat-rows tr[data-case-id]').forEach((row) => {
    row.addEventListener('click', () => openCase(Number(row.dataset.caseId)));
  });

  $('#pagination').innerHTML = Array.from({ length: pageCount }, (_, index) => index + 1).map((pageNumber) => `
    <button type="button" class="page-button ${state.page === pageNumber ? 'active' : ''}" data-page="${pageNumber}">${pageNumber}</button>
  `).join('');

  $$('.page-button').forEach((button) => {
    button.addEventListener('click', () => {
      state.page = Number(button.dataset.page);
      renderQueue();
    });
  });
}

function evidenceEvent(kind, row) {
  const fields = kind === 'email'
    ? [['date', 'Date'], ['to', 'To'], ['from', 'From'], ['attachments', 'Attachments'], ['size', 'Size']]
    : kind === 'file'
      ? [['date', 'Date'], ['filename', 'File'], ['pc', 'Endpoint']]
      : [['date', 'Date'], ['activity', 'Activity'], ['pc', 'Endpoint']];

  return `<div class="event-item">${fields.filter(([key]) => row && row[key]).map(([key, label]) => `<span><strong>${label}:</strong> ${escapeHtml(row[key])}</span>`).join(' · ')}</div>`;
}

function renderCase() {
  const caseItem = state.activeCase;
  const evidence = state.activeEvidence || {};

  if (!caseItem) {
    $('#case-detail').classList.add('hidden');
    $('#case-empty').classList.remove('hidden');
    return;
  }

  $('#case-empty').classList.add('hidden');
  $('#case-detail').classList.remove('hidden');

  const riskBucket = getRiskBucket(caseItem.probability);
  $('#case-id').textContent = `#${caseItem.id}`;
  $('#case-subject').textContent = caseItem.user;
  $('#case-date').textContent = `Alert date: ${caseItem.date || '—'}`;
  $('#risk-tag').textContent = `${riskBucket} risk`;
  $('#risk-tag').className = `risk-badge ${riskBucket.toLowerCase()}`;
  $('#confidence').textContent = `Threat confidence ${formatPercent(caseItem.probability)}`;

  const profile = caseItem.profile || {};
  $('#metrics').innerHTML = [
    ['Threat confidence', formatPercent(caseItem.probability)],
    ['USB connections', valueOrDash(profile.usb_connects)],
    ['Files copied', valueOrDash(profile.files_copied)],
    ['Emails sent', valueOrDash(profile.emails_sent)],
    ['Behavior risk score', valueOrDash(profile.behavior_risk_score)],
  ].map(([label, value]) => `
    <div class="metric-card detail-metric">
      <small>${label}</small>
      <strong>${value}</strong>
    </div>
  `).join('');

  $('#tab-overview').innerHTML = `
    <div class="detail-grid">
      <article class="detail-card">
        <h3>Observed behavioral indicators</h3>
        <ul>
          ${(Array.isArray(caseItem.indicators) ? caseItem.indicators : []).map((item) => `<li>${escapeHtml(item)}</li>`).join('') || '<li>No indicators available.</li>'}
        </ul>
      </article>
      <article class="detail-card">
        <h3>Analyst posture</h3>
        <p>The classifier has identified a notable departure from this subject’s learned behavioral baseline. Treat this as a lead, preserve evidence, and validate role context before making any action based on the model output.</p>
        <h4>Available evidence</h4>
        <ul>
          ${Object.entries(caseItem.evidence_counts || {}).map(([name, count]) => `<li>${nice(name)} events <strong>${count}</strong></li>`).join('') || '<li>No source counts available.</li>'}
        </ul>
      </article>
    </div>
  `;

  $('#tab-evidence').innerHTML = `
    <div class="evidence-grid">
      ${['logon', 'device', 'file', 'email'].map((kind) => {
        const rows = Array.isArray(evidence[kind]) ? evidence[kind] : [];
        return `
          <article class="detail-card evidence-card">
            <h3>${nice(kind)} evidence</h3>
            <div class="count-badge">${rows.length}</div>
            <div class="event-list">
              ${rows.slice(0, 12).map((row) => evidenceEvent(kind, row)).join('') || '<div class="event-item">No supplied records for this case.</div>'}
            </div>
          </article>
        `;
      }).join('')}
    </div>
  `;

  const shapValues = Array.isArray(caseItem.shap) ? caseItem.shap : [];
  const maxContribution = Math.max(...shapValues.map((entry) => Math.abs(Number(entry.contribution || 0))), 1);

  $('#tab-explainability').innerHTML = `
    <div class="detail-grid">
      <article class="detail-card">
        <h3>Local SHAP explanation</h3>
        <p>Feature magnitude reflects contribution strength, while the sign indicates the direction of model influence. This is not a causal explanation of intent.</p>
        ${shapValues.length ? shapValues.map((entry) => `
          <div class="shap-row">
            <span>${escapeHtml(entry.feature)}</span>
            <div class="bar-track"><div class="bar-fill ${Number(entry.contribution) < 0 ? 'negative' : 'positive'}" style="width:${(Math.abs(Number(entry.contribution || 0)) / maxContribution) * 100}%"></div></div>
            <span class="shap-value">${Number(entry.contribution || 0) > 0 ? '+' : ''}${Number(entry.contribution || 0).toFixed(3)}</span>
          </div>
        `).join('') : '<p class="empty-inline">No SHAP contribution data available.</p>'}
      </article>
      <article class="detail-card">
        <h3>Behavioral deviations</h3>
        <ul>
          ${(Array.isArray(caseItem.deviations) ? caseItem.deviations : []).map((item) => `<li>${escapeHtml(item)}</li>`).join('') || '<li>No behavioral deviations available.</li>'}
        </ul>
        <h4>Engineered risk features</h4>
        <ul>
          ${(Array.isArray(caseItem.risk_features) ? caseItem.risk_features : []).map((item) => `<li>${escapeHtml(item)}</li>`).join('') || '<li>No engineered risk features available.</li>'}
        </ul>
      </article>
    </div>
  `;

  activateTab(state.activeTab);
}

function activateTab(name) {
  const tabButtons = $$('.tab');
  const panels = $$('.tab-panel');
  state.activeTab = name;

  tabButtons.forEach((button) => button.classList.toggle('active', button.dataset.tab === name));
  panels.forEach((panel) => panel.classList.add('hidden'));

  const target = document.getElementById(`tab-${name}`);
  if (target) target.classList.remove('hidden');
}

async function openCase(caseId) {
  const data = await api(`/api/cases/${caseId}`);
  state.selectedCaseId = caseId;
  state.activeCase = data.case;
  state.activeEvidence = data.evidence;
  renderQueue();
  renderCase();

  const investigationSection = document.getElementById('investigations');
  if (investigationSection) {
    investigationSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function clearFilters() {
  state.search = '';
  state.riskFilter = 'all';
  state.dateFrom = '';
  state.dateTo = '';
  state.sort = 'probability-desc';
  state.page = 1;
  $('#search').value = '';
  $('#risk-filter').value = 'all';
  $('#date-from').value = '';
  $('#date-to').value = '';
  $('#sort-order').value = 'probability-desc';
  renderQueue();
}

async function start() {
  const data = await api('/api/cases');
  state.cases = Array.isArray(data.cases) ? data.cases : [];
  renderOverviewMetrics();
  renderAnalytics();
  renderQueue();

  document.querySelectorAll('.nav-link').forEach((link) => {
    link.addEventListener('click', (event) => {
      event.preventDefault();
      const target = document.querySelector(link.getAttribute('href'));
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      document.querySelectorAll('.nav-link').forEach((navLink) => navLink.classList.toggle('active', navLink === link));
    });
  });

  $('#back-to-queue').addEventListener('click', () => {
    document.getElementById('case-queue').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  $('#search').addEventListener('input', (event) => {
    state.search = event.target.value;
    state.page = 1;
    renderQueue();
  });

  $('#risk-filter').addEventListener('change', (event) => {
    state.riskFilter = event.target.value;
    state.page = 1;
    renderQueue();
  });

  $('#date-from').addEventListener('change', (event) => {
    state.dateFrom = event.target.value;
    state.page = 1;
    renderQueue();
  });

  $('#date-to').addEventListener('change', (event) => {
    state.dateTo = event.target.value;
    state.page = 1;
    renderQueue();
  });

  $('#sort-order').addEventListener('change', (event) => {
    state.sort = event.target.value;
    state.page = 1;
    renderQueue();
  });

  $('#clear-filters').addEventListener('click', clearFilters);

  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => activateTab(tab.dataset.tab));
  });
}

start().catch((error) => {
  $('#status-text').textContent = 'Dataset unavailable';
  $('#overview-metrics').innerHTML = `<div class="metric-card"><small>Overview</small><strong>Unavailable</strong><span>${escapeHtml(error.message)}</span></div>`;
  $('#case-queue').classList.add('warning');
});