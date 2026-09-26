/* ============================================================
   MASE-SE Dashboard — app.js
   Vanilla JavaScript SPA — no external frameworks
   ============================================================ */

// ─── API helper ────────────────────────────────────────────────
const API = {
  get:  url       => fetch(url).then(r => r.json()),
  post: (url, body) => fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  }).then(r => r.json()),

  stats:        ()        => API.get('/api/stats'),
  hospitals:    ()        => API.get('/api/hospitals'),
  users:        ()        => API.get('/api/users'),
  patients:     ()        => API.get('/api/patients'),
  cloud:        pid       => API.get(`/api/cloud/${pid}`),
  consent:      pid       => API.get(`/api/patients/${pid}/consent`),
  grant:        (pid, b)  => API.post(`/api/patients/${pid}/consent/grant`, b),
  revoke:       (pid, b)  => API.post(`/api/patients/${pid}/consent/revoke`, b),
  search:       body      => API.post('/api/search', body),
  audit:        (n=100)   => API.get(`/api/audit?limit=${n}`),
  performance:  ()        => API.get('/api/performance'),
  setupStatus:  ()        => API.get('/api/setup/status'),
};

// ─── Navigation ────────────────────────────────────────────────
const SECTION_TITLES = {
  overview:    'System Overview',
  users:       'Hospitals & Users',
  cloud:       'Cloud Records View',
  search:      '🔍 Search & Authorization (Demo)',
  consent:     'Consent Management',
  mpc:         '🔑 Multi-Authority MPC — Shamir (2,3)',
  delegation:  '⏱️ Temporary Delegation',
  policy:      '🔒 Protected Access Policy',
  verifiable:  '✅ Blockchain-Free Verifiable Search',
  audit:       'Audit Log',
  performance: 'Performance Benchmarks',
};

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    const section = link.dataset.section;
    switchSection(section);
  });
});

function switchSection(section) {
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  document.querySelector(`[data-section="${section}"]`).classList.add('active');
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.getElementById(`section-${section}`).classList.add('active');
  document.getElementById('page-title').textContent = SECTION_TITLES[section] || section;

  // Load section data
  if (section === 'overview')    loadOverview();
  if (section === 'users')       loadUsers();
  if (section === 'cloud')       {};
  if (section === 'search')      loadSearchUsers();
  if (section === 'consent')     {};
  if (section === 'mpc')         loadMpcSessions();
  if (section === 'delegation')  loadDelegationList();
  if (section === 'policy')      loadPolicy();
  if (section === 'verifiable')  {};
  if (section === 'audit')       loadAudit();
  if (section === 'performance') {};
}

// ─── Toast ─────────────────────────────────────────────────────
function showToast(msg, type='') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast show ${type}`;
  setTimeout(() => t.classList.remove('show'), 3000);
}

// ─── Format helpers ────────────────────────────────────────────
function fmt(n) { return n != null ? Number(n).toLocaleString() : '—'; }
function roleBadge(role) {
  const map = { Doctor:'doctor', Nurse:'nurse', Researcher:'researcher', Patient:'patient' };
  return `<span class="badge badge-${map[role]||'info'}">${role}</span>`;
}
function eventClass(t) {
  if (t === 'AUTH_GRANTED')      return 'event-auth-granted';
  if (t === 'AUTH_DENIED')       return 'event-auth-denied';
  if (t.includes('REVOKE'))      return 'event-consent-revoke';
  if (t.includes('GRANT'))       return 'event-consent-grant';
  if (t.includes('SEARCH'))      return 'event-search';
  return 'event-default';
}

// ─── Overview ──────────────────────────────────────────────────
async function loadOverview() {
  // Check setup status
  const status = await API.setupStatus();
  const notice = document.getElementById('setup-notice');
  if (notice) notice.style.display = status.ready ? 'none' : 'block';

  const data = await API.stats();
  const badge = document.getElementById('status-badge');
  if (badge) { badge.textContent = 'System Ready'; badge.className = 'badge badge-success'; }

  const grid = document.getElementById('stats-grid');
  if (!grid) return;
  const cards = [
    { v: fmt(data.total_ehr_records), l: 'Encrypted EHR Records' },
    { v: fmt(data.index_entries),     l: 'Search Index Entries' },
    { v: fmt(data.total_users),       l: 'System Users' },
    { v: fmt(data.total_patients),    l: 'Patient Actors' },
    { v: fmt(data.audit_events),      l: 'Audit Log Entries' },
    { v: fmt(Object.keys(data.by_hospital || {}).length || 3), l: 'Hospital Authorities' }
  ];
  grid.innerHTML = cards.map(c => `
    <div class="stat-card">
      <div class="stat-value">${c.v}</div>
      <div class="stat-label">${c.l}</div>
    </div>`).join('');
}

// ─── Users ─────────────────────────────────────────────────────
async function loadUsers() {
  const data = await API.users();
  const el = document.getElementById("users-tbody");
  if (!el) return;
  const users = Array.isArray(data) ? data : (data.users || []);
  el.innerHTML = users.map(u => `
    <tr>
      <td><code>${u.user_id}</code></td>
      <td>${u.full_name}</td>
      <td>${roleBadge(u.role)}</td>
      <td>${u.hospital_id}</td>
      <td><span class="badge badge-${u.status==='ACTIVE'?'success':'danger'}">${u.status}</span></td>
      <td><code class="mono" title="${u.user_hash}">${(u.user_hash||'').substring(0,24)}...</code></td>
    </tr>`).join('');
}

// ─── Cloud Records ─────────────────────────────────────────────
async function loadCloud(patientId) {
  const data = await API.cloud(patientId);
  const el = document.getElementById('cloud-records-container');
  if (!el) return;

  if (!data.records || data.records.length === 0) {
    el.innerHTML = '<div class="alert alert-warning">No records found for this patient.</div>';
    return;
  }

  const sample = data.records.slice(0, 6);
  el.innerHTML = `
    <div class="alert alert-info">
      Showing ${sample.length} of ${data.total_records} encrypted records.
      <strong>No plaintext EHR content is visible here — this is the cloud view.</strong>
    </div>
    ${sample.map(r => `
    <div class="cloud-record">
      <div class="cr-label">📄 Record: ${r.record_id}</div>
      <div><span class="cr-field">patient_hash  :</span> <span class="cr-value">${r.patient_hash}</span></div>
      <div><span class="cr-field">hospital_id   :</span> <span class="cr-value">${r.hospital_id}</span></div>
      <div><span class="cr-field">encrypted_ehr :</span> <span class="cr-value">${(r.encrypted_ehr||'').substring(0,64)}…</span></div>
      <div><span class="cr-field">nonce         :</span> <span class="cr-value">${r.nonce||''}</span></div>
      <div><span class="cr-field">sensitivity   :</span> <span class="cr-value">${r.sensitivity}</span></div>
      <div><span class="cr-field">department    :</span> <span class="cr-value">${r.department}</span></div>
    </div>`).join('')}`;
}

// ─── Search & Authorization ────────────────────────────────────
let _searchUsers = [];
async function loadSearchUsers() {
  const data = await API.users();
  _searchUsers = Array.isArray(data) ? data : (data.users || []);
  const sel = document.getElementById('search-user');
  if (!sel) return;
  sel.innerHTML = _searchUsers.map(u =>
    `<option value="${u.user_id}">${u.user_id} — ${u.full_name} (${u.role}, ${u.hospital_id})</option>`
  ).join('');
}

async function runSearch() {
  const keyword   = (document.getElementById('search-keywords')?.value || '').trim();
  const userId    = document.getElementById('search-user')?.value;
  const patientId = document.getElementById('search-patient')?.value;
  if (!keyword) { showToast('Enter a keyword', 'error'); return; }

  const data = await API.post('/api/search', { keywords: keyword, user_id: userId, patient_id: patientId }).catch(e => ({error: e.message}));
  if (data.error) { showToast(data.error, 'error'); return; }

  const condEl = document.getElementById('auth-conditions');
  const verdEl = document.getElementById('auth-verdict');
  const resEl  = document.getElementById('ehr-results');
  if (!condEl || !verdEl || !resEl) return;

  // Unhide the cards
  document.getElementById('auth-card').style.display = 'block';
  document.getElementById('results-card').style.display = 'block';

  const c = data.authorization || {};
  const cond = (label, ok) => `
    <div class="auth-cond ${ok === true ? 'cond-ok' : ok === false ? 'cond-fail' : 'cond-na'}">
      <div class="cond-label">${label}</div>
      <div class="cond-value">${ok === true ? '✓ PASS' : ok === false ? '✗ FAIL' : '—'}</div>
    </div>`;
  condEl.innerHTML =
    cond('Hospital Match',   c.hospital_match) +
    cond('Role Authorized',  c.role_match) +
    cond('Consent Active',   c.consent_active) +
    cond('Time Valid',       c.time_valid);

  const granted = data.authorization && data.authorization.allowed;
  verdEl.innerHTML = `<div class="verdict-banner ${granted ? 'verdict-granted' : 'verdict-denied'}">
    ${granted ? '🟢 ACCESS GRANTED' : '🔴 ACCESS DENIED'}
  </div>`;
  verdEl.style.display = 'block';

  const results = data.decrypted_ehrs || [];
  if (granted && results.length > 0) {
    const rows = results.slice(0, 10).map(r => `
      <tr>
        <td><code>${r.record_id}</code></td>
        <td>${r.hospital_id}</td>
        <td>${r.department}</td>
        <td>${r.admit_date || '—'}</td>
        <td>
          <button class="btn btn-primary btn-sm" onclick="decryptRecord('${r.record_id}','${userId}','${patientId}')">
            🔓 Decrypt
          </button>
        </td>
      </tr>`).join('');
    resEl.innerHTML = `
      <div class="alert alert-success">Found ${results.length} matching record(s). Showing top 10.</div>
      <table class="table">
        <thead><tr><th>Record ID</th><th>Hospital</th><th>Dept</th><th>Admit Date</th><th>Action</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  } else if (!granted) {
    resEl.innerHTML = `<div class="alert alert-danger">${data.authorization?.reason || 'Access denied.'}</div>`;
  } else {
    resEl.innerHTML = `<div class="alert alert-warning">No matching records found for keyword "${keyword}".</div>`;
  }
}

async function decryptRecord(recordId, userId, patientId) {
  const data = await API.post('/api/decrypt', { record_id: recordId, user_id: userId, patient_id: patientId });
  const el = document.getElementById('decrypted-ehr');
  if (!el) return;
  if (data.error) {
    el.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
  } else {
    const ehr = data.ehr || {};
    el.innerHTML = `
      <div class="alert alert-success">EHR successfully decrypted.</div>
      <div class="cloud-record" style="background:#0d2136">
        <div class="cr-label">📋 Decrypted EHR — ${recordId}</div>
        ${ehr.plaintext ? `<div style="margin-top:12px; padding:12px; background:#112a46; border-radius:6px;"><pre style="color:#a8c7fa; margin:0; font-size:13px; white-space:pre-wrap; word-wrap:break-word;">${ehr.plaintext}</pre></div>` : Object.entries(ehr).map(([k,v]) => `<div><span class="cr-field">${k.padEnd(20,' ')}:</span> <span class="cr-value">${v}</span></div>`).join('')}
      </div>`;
  }
  el.scrollIntoView({ behavior: 'smooth' });
}

// ─── Consent Management ────────────────────────────────────────
async function loadConsent(patientId) {
  const data  = await API.consent(patientId);
  const el    = document.getElementById('consent-table-container');
  const sumEl = document.getElementById('consent-summary');
  if (!el) return;

  const policies = data.policies || [];
  sumEl && (sumEl.textContent = `${policies.length} consent policies for ${patientId}`);

  if (policies.length === 0) {
    el.innerHTML = '<div class="alert alert-warning">No consent policies found.</div>';
    return;
  }

  el.innerHTML = `<div class="consent-grid">` +
    policies.map(p => `
      <div class="consent-card ${p.status === 'ACTIVE' ? 'active' : 'revoked'}">
        <div class="consent-hosp">${p.hospital_id}</div>
        <div class="consent-role">${p.role}</div>
        <div class="consent-status">${p.status === 'ACTIVE' ? '✅ ACTIVE' : '❌ REVOKED'}</div>
        ${p.status === 'ACTIVE'
          ? `<button class="btn btn-danger btn-sm" style="margin-top:8px"
               onclick="revokeConsent('${patientId}','${p.hospital_id}','${p.role}')">
               Revoke
             </button>`
          : `<button class="btn btn-success btn-sm" style="margin-top:8px"
               onclick="grantConsent('${patientId}','${p.hospital_id}','${p.role}')">
               Re-Grant
             </button>`}
      </div>`).join('') +
    `</div>`;
}

async function revokeConsent(patientId, hospitalId, role) {
  await API.revoke(patientId, { hospital_id: hospitalId, role });
  showToast(`Consent revoked — ${hospitalId} / ${role}`, 'error');
  await loadConsent(patientId);
}

async function grantConsent(patientId, hospitalId, role) {
  await API.grant(patientId, { hospital_id: hospitalId, role });
  showToast(`Consent granted — ${hospitalId} / ${role}`, 'success');
  await loadConsent(patientId);
}

// ─── Audit Log ─────────────────────────────────────────────────
async function loadAudit() {
  const data = await API.audit(60);
  const el = document.getElementById('audit-tbody');
  const countEl = document.getElementById('audit-count');
  if (!el) return;
  const entries = Array.isArray(data) ? data : (data.entries || []);
  if (countEl) countEl.innerText = entries.length;
  if (entries.length === 0) { el.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No audit entries yet.</td></tr>'; return; }
  el.innerHTML = entries.map(e => `
    <tr>
      <td class="audit-time" style="white-space:nowrap">${(e.timestamp||'').replace('T',' ').substring(0,19)}</td>
      <td><span class="audit-event ${eventClass(e.event_type)}">${e.event_type}</span></td>
      <td><span class="badge badge-secondary">${e.user_id || '-'}</span></td>
      <td class="audit-detail">${e.details || ''}</td>
      <td><span class="badge ${e.success ? 'badge-success' : 'badge-danger'}">${e.success ? 'OK' : 'FAIL'}</span></td>
    </tr>`).join('');
}

// ─── Performance ───────────────────────────────────────────────
async function loadPerformance() {
  const grid = document.getElementById('perf-grid');
  if (!grid) return;
  grid.innerHTML = '<div class="perf-placeholder">⏳ Running benchmarks…</div>';
  const data = await API.performance();
  const labels = {
    encrypt_avg_ms:        'AES-256-GCM Encryption',
    decrypt_avg_ms:        'AES-256-GCM Decryption',
    hash_avg_ms:           'SHA-256 Hashing',
    token_gen_avg_ms:      'HMAC Search Token Gen',
    search_avg_ms:         'Keyword Search',
    auth_check_avg_ms:     'Authorization Check',
  };
  const maxVal = Math.max(...Object.values(labels).map(k => 0),
    ...Object.keys(labels).map(k => data[k] || 0));
  grid.innerHTML = Object.entries(labels).map(([key, label]) => {
    const ms  = data[key] ?? '—';
    const pct = ms !== '—' && maxVal > 0 ? Math.min(Math.round((ms / maxVal) * 100), 100) : 0;
    return `
      <div class="perf-card">
        <div class="perf-label">${label}</div>
        <div class="perf-value">${ms} ms</div>
        <div class="perf-bar-bg"><div class="perf-bar" style="width:${pct}%"></div></div>
      </div>`;
  }).join('');
}

// ─── Auto-refresh audit ────────────────────────────────────────
setInterval(() => {
  if (document.getElementById('section-audit')?.classList.contains('active')) loadAudit();
}, 8000);

// ─── Init ──────────────────────────────────────────────────────
loadOverview();


// ═══════════════════════════════════════════════════════════════
// 40% EXTENSION — Advanced Feature JavaScript
// ═══════════════════════════════════════════════════════════════

let _mpcSessionId      = null;
let _delegationTokenId = null;
let _vfyRecordIds      = [];
let _vfyVerValue       = null;
let _vfyKeywords       = [];

// ─── MPC ───────────────────────────────────────────────────────
async function generateMPC() {
  const sel = document.getElementById('mpc-action-select');
  const action = sel ? sel.value : 'teacher_demo';
  const data = await API.post('/api/mpc/generate', { purpose: action });
  _mpcSessionId = data.session_id;

  document.getElementById('mpc-shares-grid').innerHTML = data.shares.map(s => `
    <div class="mpc-share-card">
      <div class="share-title">🏥 ${s.hospital_id.replace('_',' ')}</div>
      <div class="share-label">x-coordinate</div>
      <div class="share-value">${s.x}</div>
      <div class="share-label">y-share (partial secret)</div>
      <div class="share-value">${s.y_hex_short}</div>
    </div>`).join('');

  document.getElementById('mpc-reconstruct-result').innerHTML = '';
  document.getElementById('mpc-shares-display').style.display = 'block';
  document.getElementById('mpc-sessions-list').innerHTML = `
    <div class="alert alert-info" style="font-size:13px">
      <strong>Session ID:</strong> <span class="mono">${data.session_id}</span><br>
      <strong>Secret hash (SHA-256):</strong> <span class="mono">${data.secret_hash}</span><br>
      <em>The actual secret is NOT stored — only shares and its SHA-256 hash are kept.</em>
    </div>`;
  showToast('Shamir (2,3) shares generated!', 'success');
}

async function reconstructMPC(hospitals) {
  if (!_mpcSessionId) { showToast('Generate a session first.', 'error'); return; }
  const data = await API.post('/api/mpc/reconstruct', { session_id: _mpcSessionId, hospitals });
  const cls  = data.success ? 'success' : 'failed';
  const icon = data.success ? '✅' : '❌';
  document.getElementById('mpc-reconstruct-result').innerHTML = `
    <div class="reconstruct-box ${cls}">
      <div class="big-status">${icon} ${data.success ? 'RECONSTRUCTION SUCCESS' : 'RECONSTRUCTION FAILED'}</div>
      <div><strong>Hospitals used:</strong> ${(data.hospitals_used || hospitals).join(', ')}</div>
      <div><strong>Shares provided:</strong> ${data.shares_used} &nbsp; <strong>Threshold required:</strong> ${data.threshold}</div>
      <div style="margin-top:6px">${data.message}</div>
      ${data.success ? `<div style="font-size:11px;font-family:monospace;opacity:.7;margin-top:4px">
        Reconstructed: ${(data.reconstructed_hex||'').substring(0,20)}…</div>` : ''}
    </div>`;
}

async function loadMpcSessions() {
  const data = await API.get('/api/mpc/sessions');
  const el   = document.getElementById('mpc-sessions-list');
  if (!el || !data.sessions || !data.sessions.length) return;
  const rows = data.sessions.slice(0,5).map(s => `
    <tr>
      <td class="mono">${s.session_id.substring(0,16)}…</td>
      <td>${s.created_at}</td>
      <td>${s.threshold}-of-${s.n_shares}</td>
      <td>${s.purpose}</td>
    </tr>`).join('');
  el.innerHTML = `
    <h4>Recent MPC Sessions</h4>
    <table class="table"><thead><tr><th>Session ID</th><th>Created</th><th>Scheme</th><th>Purpose</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

// ─── Delegation ────────────────────────────────────────────────
async function createDelegation() {
  const body = {
    delegator:        document.getElementById('del-delegator').value,
    delegatee:        document.getElementById('del-delegatee').value,
    patient_id:       document.getElementById('del-patient').value,
    hospital_id:      document.getElementById('del-hospital').value,
    role:             'Doctor',
    duration_minutes: parseInt(document.getElementById('del-duration').value) || 60,
    scope:            document.getElementById('del-scope').value,
  };
  const data = await API.post('/api/delegation/create', body);
  if (data.error) { showToast('Error: ' + data.error, 'error'); return; }
  _delegationTokenId = data.token_id;

  document.getElementById('delegation-token-info').innerHTML = `
    <div class="token-info-box">
      <div><strong>Token ID:</strong> <span class="mono">${data.token_id}</span></div>
      <div><strong>Delegator:</strong> ${data.delegator} → <strong>Delegatee:</strong> ${data.delegatee}</div>
      <div><strong>Patient:</strong> ${data.patient_id} &nbsp; <strong>Hospital:</strong> ${data.hospital_id}</div>
      <div><strong>Scope:</strong> ${data.scope} &nbsp; <strong>Issued:</strong> ${data.issued_at}</div>
      <div><strong>Expires:</strong> ${data.expires_at}</div>
      <div style="margin-top:8px"><strong>HMAC-SHA256 Signature:</strong></div>
      <div class="token-sig">✓ ${data.signature}</div>
      <div style="margin-top:6px;font-size:12px;color:#16a34a"><strong>Token Created ✓ &nbsp; Signature Valid ✓</strong></div>
    </div>`;
  document.getElementById('delegation-token-display').style.display = 'block';
  document.getElementById('delegation-validate-result').innerHTML = '';
  await loadDelegationList();
  showToast('Delegation token created!', 'success');
}

async function validateDelegation(simulateExpired = false) {
  if (!_delegationTokenId) { showToast('Create a token first.', 'error'); return; }
  const delegatee  = document.getElementById('del-delegatee').value;
  const patient_id = document.getElementById('del-patient').value;

  let data;
  if (simulateExpired) {
    data = await API.post('/api/delegation/validate_expired', {
      token_id: _delegationTokenId, requesting_user: delegatee, patient_id
    });
  } else {
    data = await API.post('/api/delegation/validate', {
      token_id: _delegationTokenId, requesting_user: delegatee, patient_id, operation: 'search'
    });
  }

  const checkRow = (label, val) => {
    const icon = val === true  ? '<span class="check-yes">✓ VALID</span>'
               : val === false ? '<span class="check-no">✗ FAILED</span>'
               : '<span style="color:#64748b">N/A</span>';
    return `<div class="validation-row"><span style="min-width:180px;font-weight:600">${label}</span>${icon}</div>`;
  };

  const bannerCls = data.valid ? 'verdict-banner verdict-granted' : 'verdict-banner verdict-denied';
  document.getElementById('delegation-validate-result').innerHTML = `
    <div class="${bannerCls}">${data.valid ? '🟢 ACCESS GRANTED' : '🔴 ACCESS DENIED'}</div>
    <div class="token-info-box" style="margin-top:8px">
      ${checkRow('Signature Valid',         data.sig_valid)}
      ${checkRow('Time Valid (not expired)',data.time_valid)}
      ${checkRow('Delegatee Match',         data.delegatee_match)}
      ${checkRow('Patient Match',           data.patient_match)}
      ${checkRow('Scope Valid',             data.scope_valid)}
      ${checkRow('Consent Active',          data.consent_active)}
      <div style="margin-top:8px;font-size:12px;color:#475569">${data.reason}</div>
      ${simulateExpired ? '<div style="margin-top:4px;font-size:12px;color:#ea580c">⚠️ Simulated expiry — token expires_at was set to the past for this demonstration.</div>' : ''}
    </div>`;
}

async function loadDelegationList() {
  const patient_id = document.getElementById('del-patient')?.value;
  if (!patient_id) return;
  const data = await API.get(`/api/delegation/list?patient_id=${patient_id}`);
  const el   = document.getElementById('delegation-list');
  if (!el || !data.tokens || !data.tokens.length) { if(el) el.innerHTML=''; return; }
  const rows = data.tokens.map(t => `
    <tr>
      <td class="mono">${t.token_id.substring(0,12)}…</td>
      <td>${t.delegator} → ${t.delegatee}</td>
      <td>${t.scope}</td>
      <td>${t.expires_at}</td>
      <td>${t.revoked ? '<span style="color:red">Revoked</span>' : '<span style="color:green">Active</span>'}</td>
    </tr>`).join('');
  el.innerHTML = `
    <h4 style="margin-top:16px">Delegation Tokens for ${patient_id}</h4>
    <table class="table"><thead><tr><th>Token ID</th><th>Delegator → Delegatee</th><th>Scope</th><th>Expires</th><th>Status</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

// ─── Protected Policy ──────────────────────────────────────────
async function loadPolicy() {
  const patient_id = document.getElementById('policy-patient')?.value;
  if (!patient_id) return;
  const data = await API.get(`/api/policy/${patient_id}`);
  const el   = document.getElementById('policy-display');
  if (!el) return;

  if (!data.protected_policies || !data.protected_policies.length) {
    el.innerHTML = '<div class="alert alert-warning">No consent policies found for this patient.</div>'; return;
  }

  const cards = data.protected_policies.map(pp => `
    <div class="policy-comparison" style="margin-bottom:16px">
      <div class="policy-side logical">
        <h5>🟢 Application (Logical) View</h5>
        <div class="policy-row"><span class="label">Hospital:</span> <span class="val">${pp.logical_view.hospital}</span></div>
        <div class="policy-row"><span class="label">Role:</span>     <span class="val">${pp.logical_view.role}</span></div>
        <div class="policy-row"><span class="label">Status:</span>   <span class="val">${pp.logical_view.status}</span></div>
        <div class="policy-row"><span class="label">Patient:</span>  <span class="val">${pp.logical_view.patient}</span></div>
        <div style="font-size:11px;color:#64748b;margin-top:8px">This is what the authorization layer sees. Not stored in cloud.</div>
      </div>
      <div class="policy-side cloud">
        <h5>🔵 Cloud (Protected) View</h5>
        <div class="policy-row"><span class="label">Policy ID:</span>    <span class="val protected">${pp.cloud_view.policy_id}</span></div>
        <div class="policy-row"><span class="label">Hosp (HMAC):</span>  <span class="val protected">${pp.cloud_view.protected_hospital}</span></div>
        <div class="policy-row"><span class="label">Role (HMAC):</span>  <span class="val protected">${pp.cloud_view.protected_role}</span></div>
        <div class="policy-row"><span class="label">Status (HMAC):</span><span class="val protected">${pp.cloud_view.protected_status}</span></div>
        <div style="font-size:11px;color:#64748b;margin-top:8px">HMAC commitments — cloud cannot recover plaintext attributes.</div>
      </div>
    </div>`).join('<hr>');

  el.innerHTML = `
    <div class="alert alert-info" style="font-size:12px;margin-bottom:12px">
      <strong>Patient:</strong> ${data.patient_id} &nbsp;|&nbsp;
      <strong>Hash:</strong> <span class="mono">${data.patient_hash}</span> &nbsp;|&nbsp;
      <strong>Policies:</strong> ${data.total_policies}<br>
      <em>${data.disclaimer}</em>
    </div>${cards}`;
}

// ─── Verifiable Search ─────────────────────────────────────────
async function runVerifiableSearch() {
  const kwStr    = document.getElementById('vfy-keywords')?.value || '';
  const patient  = document.getElementById('vfy-patient')?.value;
  const keywords = kwStr.split(/\s+/).filter(k => k.length > 0);
  if (!keywords.length) { showToast('Enter at least one keyword.', 'error'); return; }

  const searchData = await API.post('/api/search', {
    keywords: keywords[0], user_id: 'DOCTOR_001', patient_id: patient
  });
  _vfyKeywords  = keywords;
  _vfyRecordIds = (searchData.search?.record_ids || []).slice(0,20);

  const vData = await API.post('/api/verify', { keywords, record_ids: _vfyRecordIds });
  _vfyVerValue = vData.verification_value;

  document.getElementById('vfy-search-info').innerHTML = `
    <div class="vfy-info-box">
      <div class="vfy-row"><div class="label">Query (normalized)</div><div class="val">${vData.query_normalized}</div></div>
      <div class="vfy-row"><div class="label">Query Hash (SHA-256)</div><div class="val">${vData.query_hash}</div></div>
      <div class="vfy-row"><div class="label">Records Returned</div><div class="val">${_vfyRecordIds.length} records</div></div>
      <div class="vfy-row"><div class="label">Verification Value (HMAC)</div><div class="val">${vData.verification_value}</div></div>
      <div class="vfy-row"><div class="label">Algorithm</div><div class="val">${vData.algorithm}</div></div>
    </div>`;
  document.getElementById('vfy-result').style.display = 'block';
  document.getElementById('vfy-verify-result').innerHTML = '';
  showToast('Search done. Verification value computed.', 'success');
}

async function verifyResults(tamper = false) {
  if (!_vfyVerValue) { showToast('Run a search first.', 'error'); return; }
  let ids = [..._vfyRecordIds];
  if (tamper) ids.push('TAMPERED_FAKE_RECORD_9999');

  const data = await API.post('/api/verify', {
    keywords: _vfyKeywords, record_ids: ids, expected_verification_value: _vfyVerValue
  });
  const cls = data.verified ? 'verified' : 'failed';
  document.getElementById('vfy-verify-result').innerHTML = `
    <div class="vfy-status-box ${cls}">${data.verified ? '✅ VERIFIED' : '❌ INTEGRITY FAILURE'}</div>
    <div class="token-info-box" style="margin-top:8px;font-size:13px">
      <div><strong>Status:</strong> ${data.status}</div>
      <div><strong>Records checked:</strong> ${ids.length}${tamper ? ' (1 fake record injected)' : ''}</div>
      <div><strong>Expected HMAC:</strong> <span class="mono">${data.expected_value.substring(0,24)}…</span></div>
      <div><strong>Computed HMAC:</strong> <span class="mono">${data.computed_value.substring(0,24)}…</span></div>
      <div style="margin-top:6px">${data.message}</div>
      ${tamper ? '<div style="color:#dc2626;font-size:12px;margin-top:4px">⚠️ 1 fake record injected. Verification correctly detected tampering.</div>' : ''}
    </div>`;
}

// ─── Advanced Performance ──────────────────────────────────────
async function loadAdvancedPerformance() {
  const grid = document.getElementById('perf-grid');
  if (!grid) return;
  grid.innerHTML = '<div class="perf-placeholder">⏳ Running advanced benchmarks…</div>';
  const data = await fetch('/api/performance/advanced').then(r => r.json());
  const m    = data.measurements;
  const labels = {
    mpc_share_generation_ms:      'MPC Share Generation (Shamir)',
    mpc_reconstruction_ms:        'MPC Reconstruction (2-of-3)',
    delegation_token_gen_ms:      'Delegation Token Generation',
    delegation_token_validate_ms: 'Delegation Token Validation',
    policy_hiding_build_ms:       'Policy Hiding — Build',
    policy_match_ms:              'Policy Hiding — Match',
    verify_compute_ms:            'Verify — Compute Accumulator',
    verify_check_ms:              'Verify — Check Result Set',
    aes_encrypt_ms:               'AES-256-GCM Encryption (baseline)',
    hmac_token_gen_ms:            'HMAC Search Token Gen (baseline)',
  };
  const maxVal = Math.max(...Object.values(m).filter(v => v > 0), 1);
  grid.innerHTML = Object.entries(labels).map(([key, label]) => {
    const ms  = m[key] ?? '—';
    const pct = (ms !== '—') ? Math.min(Math.round((ms / maxVal) * 100), 100) : 0;
    return `
      <div class="perf-card">
        <div class="perf-label">${label}</div>
        <div class="perf-value">${ms} ms</div>
        <div class="perf-bar-bg"><div class="perf-bar" style="width:${pct}%"></div></div>
      </div>`;
  }).join('');
}
