/* ── Sidebar toggle ──────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  const sidebar  = document.getElementById('sidebar');
  const main     = document.getElementById('main');
  const toggle   = document.getElementById('sidebarToggle');
  const mToggle  = document.getElementById('sidebarToggleMobile');

  if (toggle) {
    toggle.addEventListener('click', () => {
      const collapsed = sidebar.style.width === '60px';
      sidebar.style.width  = collapsed ? '240px' : '60px';
      main.style.marginLeft = collapsed ? '240px' : '60px';
      sidebar.querySelectorAll('.nav-item a span, .logo span, .nav-section span, .sidebar-footer').forEach(el => {
        el.style.opacity = collapsed ? '1' : '0';
        el.style.width   = collapsed ? 'auto' : '0';
        el.style.overflow = 'hidden';
      });
    });
  }

  if (mToggle) {
    mToggle.addEventListener('click', () => sidebar.classList.toggle('open'));
    document.addEventListener('click', e => {
      if (!sidebar.contains(e.target) && !mToggle.contains(e.target)) sidebar.classList.remove('open');
    });
  }
});

/* ── Tabs ────────────────────────────────────────────────────────── */
function initTabs(container) {
  const tabs   = container.querySelectorAll('.tab-btn');
  const panels = container.querySelectorAll('.tab-panel');
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const target = container.querySelector(`#${btn.dataset.tab}`);
      if (target) target.classList.add('active');
    });
  });
}

document.querySelectorAll('.tab-container').forEach(initTabs);

/* ── API helper ──────────────────────────────────────────────────── */
async function apiPost(endpoint, data, outputEl) {
  setOutput(outputEl, '<span class="spinner"></span> Running…', false);
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const json = await res.json();
    return json;
  } catch (err) {
    setOutput(outputEl, `<span class="output-line error">Error: ${err.message}</span>`);
    return null;
  }
}

/* ── Output rendering ────────────────────────────────────────────── */
function setOutput(el, html, raw = true) {
  if (!el) return;
  el.innerHTML = raw ? `<pre style="background:none;padding:0;color:inherit">${escHtml(html)}</pre>` : html;
}

function renderJSON(el, data, label = '') {
  if (!el) return;
  if (data && data.error) {
    el.innerHTML = `<span class="output-line error">✗ Error: ${escHtml(data.error)}</span>`;
    return;
  }
  let html = label ? `<span class="output-line heading">${escHtml(label)}</span>\n` : '';
  html += `<pre style="background:none;padding:0;color:#a8dadc">${escHtml(JSON.stringify(data, null, 2))}</pre>`;
  el.innerHTML = html;
}

function renderTable(el, rows, cols) {
  if (!el || !rows || rows.length === 0) {
    el.innerHTML = '<span class="output-line warning">No results found.</span>';
    return;
  }
  let html = '<table class="data-table"><thead><tr>';
  cols.forEach(c => { html += `<th>${escHtml(c.label || c.key)}</th>`; });
  html += '</tr></thead><tbody>';
  rows.forEach(row => {
    html += '<tr>';
    cols.forEach(c => {
      const val = row[c.key] ?? '';
      html += `<td>${c.render ? c.render(val, row) : escHtml(String(val))}</td>`;
    });
    html += '</tr>';
  });
  html += '</tbody></table>';
  el.innerHTML = html;
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ── Copy to clipboard ───────────────────────────────────────────── */
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    btn.style.color = 'var(--success)';
    setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
  });
}

document.addEventListener('click', e => {
  if (e.target.classList.contains('copy-btn')) {
    const box = e.target.closest('.output-box');
    if (box) copyText(box.innerText.replace('📋 Copy','').trim(), e.target);
  }
});

/* ── Port scan renderer ──────────────────────────────────────────── */
function renderPortScan(el, data) {
  if (!el) return;
  if (data.error) { el.innerHTML = `<span class="output-line error">✗ ${escHtml(data.error)}</span>`; return; }
  let html = `<span class="output-line heading">Port Scan: ${escHtml(data.target)} (${escHtml(data.ip||'')})</span>\n`;
  html += `<span class="output-line info">Scanned: ${data.total_scanned} ports | Open: ${data.open_ports?.length || 0}</span>\n\n`;
  if (data.open_ports?.length) {
    html += '<table class="data-table"><thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead><tbody>';
    data.open_ports.forEach(p => {
      html += `<tr><td><strong>${p.port}</strong></td><td><span class="badge badge-open">OPEN</span></td><td>${escHtml(p.service||'')}</td></tr>`;
    });
    html += '</tbody></table>';
  } else {
    html += '<span class="output-line warning">No open ports found.</span>';
  }
  el.innerHTML = html;
}

/* ── DNS renderer ────────────────────────────────────────────────── */
function renderDNS(el, data) {
  if (!el) return;
  if (data.error) { el.innerHTML = `<span class="output-line error">✗ ${escHtml(data.error)}</span>`; return; }
  let html = `<span class="output-line heading">DNS Lookup: ${escHtml(data.target)}</span>\n`;
  if (data.ip) html += `<span class="output-line info">IP Address: ${escHtml(data.ip)}</span>\n`;
  if (data.reverse_dns) html += `<span class="output-line info">Reverse DNS: ${escHtml(data.reverse_dns)}</span>\n\n`;
  const records = data.records || {};
  if (Object.keys(records).length === 0) { html += '<span class="output-line warning">No DNS records found.</span>'; }
  else {
    Object.entries(records).forEach(([type, vals]) => {
      html += `<span class="output-line heading">${escHtml(type)} Records:</span>\n`;
      vals.forEach(v => { html += `  <span class="output-line success">  ${escHtml(v)}</span>\n`; });
    });
  }
  el.innerHTML = html;
}

/* ── Headers renderer ────────────────────────────────────────────── */
function renderHeaders(el, data) {
  if (!el) return;
  if (data.error) { el.innerHTML = `<span class="output-line error">✗ ${escHtml(data.error)}</span>`; return; }
  let html = `<span class="output-line heading">HTTP Headers: ${escHtml(data.url)}</span>\n`;
  html += `<span class="output-line info">Status: ${escHtml(String(data.status_code||''))}</span>\n\n`;
  if (data.security_headers) {
    html += '<span class="output-line heading">Security Headers:</span>\n';
    Object.entries(data.security_headers).forEach(([k, v]) => {
      const cls = v === 'MISSING' ? 'error' : 'success';
      const icon = v === 'MISSING' ? '✗' : '✓';
      html += `  <span class="output-line ${cls}">${icon} ${escHtml(k)}: ${escHtml(v)}</span>\n`;
    });
  }
  if (data.headers) {
    html += '\n<span class="output-line heading">All Headers:</span>\n';
    Object.entries(data.headers).forEach(([k, v]) => {
      html += `  <span class="output-line">${escHtml(k)}: ${escHtml(v)}</span>\n`;
    });
  }
  el.innerHTML = html;
}

/* ── Vuln renderer ───────────────────────────────────────────────── */
function renderVulns(el, data, label) {
  if (!el) return;
  if (data.error) { el.innerHTML = `<span class="output-line error">✗ ${escHtml(data.error)}</span>`; return; }
  let html = `<span class="output-line heading">${escHtml(label)}: ${escHtml(data.target||data.url||'')}</span>\n\n`;
  const vulns = data.vulnerabilities || [];
  if (vulns.length === 0) {
    html += '<span class="output-line success">✓ No vulnerabilities detected with automated tests.</span>\n';
    (data.info || []).forEach(i => { html += `<span class="output-line info">ℹ ${escHtml(i)}</span>\n`; });
  } else {
    vulns.forEach(v => {
      html += `<span class="output-line error">✗ [${escHtml(v.severity)}] ${escHtml(v.type)}</span>\n`;
      html += `  <span class="output-line warning">  Payload: ${escHtml(v.payload||'')}</span>\n`;
      if (v.evidence) html += `  <span class="output-line info">  Evidence: ${escHtml(v.evidence)}</span>\n`;
      html += `  <span class="output-line">  URL: ${escHtml(v.url||'')}</span>\n\n`;
    });
  }
  el.innerHTML = html;
}

/* ── Subdomain renderer ──────────────────────────────────────────── */
function renderSubdomains(el, data) {
  if (!el) return;
  if (data.error) { el.innerHTML = `<span class="output-line error">✗ ${escHtml(data.error)}</span>`; return; }
  let html = `<span class="output-line heading">Subdomain Enumeration: ${escHtml(data.domain)}</span>\n`;
  html += `<span class="output-line info">Found: ${data.count || 0} subdomains</span>\n\n`;
  if (data.found?.length) {
    html += '<table class="data-table"><thead><tr><th>Subdomain</th><th>IP</th></tr></thead><tbody>';
    data.found.forEach(s => {
      html += `<tr><td>${escHtml(s.subdomain)}</td><td>${escHtml(s.ip||'')}</td></tr>`;
    });
    html += '</tbody></table>';
  } else {
    html += '<span class="output-line warning">No subdomains resolved.</span>';
  }
  el.innerHTML = html;
}

/* ── SSL renderer ────────────────────────────────────────────────── */
function renderSSL(el, data) {
  if (!el) return;
  if (data.error && !data.valid) { el.innerHTML = `<span class="output-line error">✗ ${escHtml(data.error)}</span>`; return; }
  let html = `<span class="output-line heading">SSL/TLS Check: ${escHtml(data.host)}</span>\n\n`;
  html += `<span class="output-line ${data.valid ? 'success' : 'error'}">${data.valid ? '✓' : '✗'} Certificate: ${data.valid ? 'VALID' : 'INVALID'}</span>\n`;
  if (data.protocol) html += `<span class="output-line info">Protocol: ${escHtml(data.protocol)}</span>\n`;
  if (data.cipher) html += `<span class="output-line info">Cipher: ${escHtml(data.cipher.name)} (${escHtml(String(data.cipher.bits))} bits)</span>\n`;
  if (data.subject) html += `<span class="output-line">Subject: ${escHtml(JSON.stringify(data.subject))}</span>\n`;
  if (data.issuer) html += `<span class="output-line">Issuer: ${escHtml(JSON.stringify(data.issuer))}</span>\n`;
  if (data.not_after) html += `<span class="output-line">Expires: ${escHtml(data.not_after)}</span>\n`;
  if (data.san?.length) html += `<span class="output-line">SANs: ${escHtml(data.san.join(', '))}</span>\n`;
  if (data.issues?.length) {
    html += '\n<span class="output-line heading">Issues:</span>\n';
    data.issues.forEach(i => { html += `  <span class="output-line error">✗ ${escHtml(i)}</span>\n`; });
  } else if (data.valid) {
    html += '\n<span class="output-line success">✓ No issues detected.</span>\n';
  }
  el.innerHTML = html;
}
