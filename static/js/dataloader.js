// ─── Data Loader Section ───────────────────────────────────────
// (appended by 40%+dataloader extension)

SECTION_TITLES['dataloader'] = 'Data Loader';

let _csvContent  = null;
let _csvFileName = null;

// Wire into switchSection
const _dlOrigSwitch = switchSection;
switchSection = function(section) {
  _dlOrigSwitch(section);
  if (section === 'dataloader') loadDataloaderStatus();
};

async function loadDataloaderStatus() {
  try {
    const data = await fetch('/api/dataloader/status').then(r => r.json());
    const banner = document.getElementById('dl-status-banner');
    const text   = document.getElementById('dl-status-text');
    const badge  = document.getElementById('dl-source-badge');
    if (!banner) return;

    const srcMap = { dummy:'Dummy Dataset', mimic:'MIMIC-IV', custom:'Custom CSV', none:'No Data' };
    const srcCls = { dummy:'badge-info', mimic:'badge-success', custom:'badge-warning', none:'badge-danger' };
    text.textContent  = data.ready
      ? 'Database loaded: ' + data.ehr_records.toLocaleString() + ' EHR records, ' + data.search_index.toLocaleString() + ' search index entries'
      : 'No data loaded yet. Choose a dataset below.';
    badge.textContent = srcMap[data.source] || 'Unknown';
    badge.className   = 'badge ' + (srcCls[data.source] || 'badge-info');
    banner.className  = 'dl-status-banner ' + (data.ready ? 'ready' : 'empty');
  } catch(e) {
    console.error('dataloader status error:', e);
  }
}

async function loadDummyDataset() {
  const btn = document.getElementById('btn-load-dummy');
  const res = document.getElementById('dl-dummy-result');
  btn.textContent = 'Loading… (~5 seconds)';
  btn.disabled = true;
  res.innerHTML = '<div class="dl-progress"><div class="dl-progress-bar" id="dl-prog" style="width:0%"></div></div>';

  let pct = 0;
  const tick = setInterval(function() {
    pct = Math.min(pct + 8, 88);
    const bar = document.getElementById('dl-prog');
    if (bar) bar.style.width = pct + '%';
  }, 350);

  try {
    const resp = await fetch('/api/dataloader/load-dummy', { method: 'POST' });
    const data = await resp.json();
    clearInterval(tick);
    const bar = document.getElementById('dl-prog');
    if (bar) bar.style.width = '100%';

    if (data.success) {
      res.innerHTML =
        '<div class="dl-result-ok">' +
        '<strong>&#9989; Dummy dataset loaded!</strong><br>' +
        'Records: <strong>' + data.records.toLocaleString() + '</strong> &nbsp;|&nbsp; ' +
        'Search index: <strong>' + data.search_index.toLocaleString() + '</strong> entries<br>' +
        '<em style="font-size:11px">All records are AES-256-GCM encrypted and HMAC-indexed.</em>' +
        '</div>';
      await loadDataloaderStatus();
      showToast('Dummy dataset loaded!', 'success');
    } else {
      res.innerHTML = '<div class="dl-result-fail">&#10060; ' + data.message + '</div>';
    }
  } catch (e) {
    clearInterval(tick);
    res.innerHTML = '<div class="dl-result-fail">&#10060; Error: ' + e.message + '</div>';
  }
  btn.textContent = '&#9889; Load Dummy Dataset';
  btn.disabled = false;
}

function handleCsvFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  _csvFileName = file.name;
  const reader = new FileReader();
  reader.onload = function(e) { _csvContent = e.target.result; showCsvPreview(); };
  reader.readAsText(file);
}

function handleCsvDrop(event) {
  event.preventDefault();
  const area = document.getElementById('dl-upload-area');
  if (area) area.classList.remove('drag-over');
  const file = event.dataTransfer.files[0];
  if (!file || !file.name.endsWith('.csv')) { showToast('Please drop a .csv file.', 'error'); return; }
  _csvFileName = file.name;
  const reader = new FileReader();
  reader.onload = function(e) { _csvContent = e.target.result; showCsvPreview(); };
  reader.readAsText(file);
}

function showCsvPreview() {
  if (!_csvContent) return;
  const lines   = _csvContent.trim().split('\n');
  const preview = document.getElementById('dl-custom-preview');
  const info    = document.getElementById('dl-custom-preview-info');
  if (!preview || !info) return;
  info.innerHTML =
    '<strong>&#128196; ' + _csvFileName + '</strong><br>' +
    'Rows detected: <strong>' + (lines.length - 1) + '</strong> data rows + 1 header<br>' +
    '<em style="font-size:11px">Click "Load This Dataset" to validate and import.</em>';
  preview.style.display = 'block';
  document.getElementById('dl-custom-result').innerHTML = '';
}

function clearCustomCsv() {
  _csvContent  = null;
  _csvFileName = null;
  const p = document.getElementById('dl-custom-preview');
  if (p) p.style.display = 'none';
  document.getElementById('dl-custom-result').innerHTML = '';
  const fi = document.getElementById('csv-file-input');
  if (fi) fi.value = '';
}

async function uploadCustomCsv() {
  if (!_csvContent) { showToast('No CSV selected.', 'error'); return; }
  const res = document.getElementById('dl-custom-result');
  res.innerHTML = '<div class="dl-result-warn">&#9203; Validating and loading…</div>';

  try {
    const resp = await fetch('/api/dataloader/load-custom', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ csv_content: _csvContent }),
    });
    const data = await resp.json();

    if (data.success) {
      const warns = (data.warnings && data.warnings.length)
        ? '<div style="margin-top:6px;color:#9a3412">' + data.warnings.join('<br>') + '</div>' : '';
      const errs  = (data.errors && data.errors.length)
        ? '<div class="dl-error-list">' + data.errors.map(function(e){ return '• ' + e; }).join('<br>') + '</div>' : '';
      const skipped = data.skipped ? ' &nbsp;|&nbsp; Skipped: <strong>' + data.skipped + '</strong>' : '';
      res.innerHTML =
        '<div class="dl-result-ok">' +
        '&#9989; <strong>Custom dataset loaded!</strong><br>' +
        'Records: <strong>' + data.records + '</strong> &nbsp;|&nbsp; ' +
        'Search index: <strong>' + data.search_index + '</strong> entries' + skipped +
        warns + errs + '</div>';
      await loadDataloaderStatus();
      showToast('Custom dataset loaded!', 'success');
    } else {
      const errs = (data.errors && data.errors.length)
        ? '<div class="dl-error-list">' + data.errors.map(function(e){ return '• ' + e; }).join('<br>') + '</div>' : '';
      res.innerHTML =
        '<div class="dl-result-fail">' +
        '&#10060; <strong>Load failed:</strong> ' + data.message + errs +
        '<div style="margin-top:8px;font-size:12px">Download the template CSV and fix the issues.</div>' +
        '</div>';
    }
  } catch (e) {
    res.innerHTML = '<div class="dl-result-fail">&#10060; Error: ' + e.message + '</div>';
  }
}

function toggleGuide() {
  const guide = document.getElementById('format-guide');
  const tog   = document.getElementById('guide-toggle');
  if (!guide) return;
  if (guide.style.display === 'none') {
    guide.style.display = 'block';
    if (tog) tog.textContent = '▲ Click to collapse';
  } else {
    guide.style.display = 'none';
    if (tog) tog.textContent = '▼ Click to expand';
  }
}
