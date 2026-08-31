const alerts = [
  { id: 'ALT-4821', severity: 'critical', name: 'Suspected command-and-control beaconing', source: 'Firewall anomaly detection', entity: 'WS-FIN-023', detail: '185.220.101.42', mitre: 'T1071.001', time: '4 min ago', status: 'new' },
  { id: 'ALT-4819', severity: 'critical', name: 'Impossible travel authentication', source: 'Azure AD sign-in analytics', entity: 'n.levy@contoso.io', detail: 'Tel Aviv → Singapore', mitre: 'T1078', time: '12 min ago', status: 'investigating' },
  { id: 'ALT-4817', severity: 'high', name: 'Multiple failed logons followed by success', source: 'Windows Security event 4625', entity: 'svc-backup', detail: '10.10.14.37', mitre: 'T1110', time: '21 min ago', status: 'new' },
  { id: 'ALT-4814', severity: 'high', name: 'Privileged group membership changed', source: 'Active Directory audit', entity: 'a.coen', detail: 'Domain Admins', mitre: 'T1098', time: '38 min ago', status: 'investigating' },
  { id: 'ALT-4808', severity: 'medium', name: 'PowerShell encoded command detected', source: 'Microsoft Defender for Endpoint', entity: 'ENG-LT-041', detail: 'powershell.exe', mitre: 'T1059.001', time: '1h 08m ago', status: 'resolved' },
  { id: 'ALT-4803', severity: 'medium', name: 'Unusual outbound data transfer', source: 'Proxy traffic analytics', entity: 'DESIGN-012', detail: '2.4 GB to external host', mitre: 'T1041', time: '1h 47m ago', status: 'new' }
];

const recentEvents = [
  ['09:42:18', 'User sign-in failure', 'WIN-DC01 · Event ID 4625', 'WINDOWS'],
  ['09:41:53', 'TLS connection blocked', 'FW-EDGE-01 · 185.220.101.42', 'FIREWALL'],
  ['09:41:15', 'Process creation', 'WS-FIN-023 · powershell.exe', 'EDR'],
  ['09:39:02', 'Conditional access evaluated', 'Azure AD · n.levy@contoso.io', 'IDENTITY']
];

function renderAlerts() {
  const query = document.querySelector('#searchInput').value.toLowerCase();
  const severity = document.querySelector('#severityFilter').value;
  const status = document.querySelector('#statusFilter').value;
  const filtered = alerts.filter(a => (severity === 'all' || a.severity === severity) && (status === 'all' || a.status === status) && Object.values(a).join(' ').toLowerCase().includes(query));
  document.querySelector('#alertRows').innerHTML = filtered.map(a => `<tr><td><span class="severity ${a.severity}">${a.severity}</span></td><td><span class="alert-name">${a.name}</span><span class="alert-sub">${a.id} · ${a.source}</span></td><td><span class="alert-name">${a.entity}</span><span class="entity-sub">${a.detail}</span></td><td class="mitre">${a.mitre}</td><td>${a.time}</td><td><span class="status ${a.status}">${a.status}</span></td><td><button class="row-action" data-id="${a.id}" aria-label="Triage ${a.id}">›</button></td></tr>`).join('');
  document.querySelector('#emptyState').hidden = filtered.length !== 0;
  document.querySelectorAll('.row-action').forEach(btn => btn.addEventListener('click', () => triage(btn.dataset.id)));
}

function triage(id) {
  const alert = alerts.find(a => a.id === id);
  if (alert.status === 'new') alert.status = 'investigating';
  else if (alert.status === 'investigating') alert.status = 'resolved';
  else alert.status = 'new';
  renderAlerts();
  showToast(`${id} marked as ${alert.status}`);
}

function renderCoverage() {
  const coverage = [['Authentication attacks', 84, 18], ['Execution', 61, 9], ['Persistence', 43, 4], ['Command & Control', 76, 13]];
  document.querySelector('#coverageList').innerHTML = coverage.map(([name, score, hits]) => `<div class="coverage-row"><b>${name}</b><div class="bar"><i style="width:${score}%"></i></div><span>${hits} hits</span></div>`).join('');
}

function renderEvents() {
  document.querySelector('#eventList').innerHTML = recentEvents.map(([time, title, meta, source]) => `<div class="event-item"><span class="event-time">${time}</span><div><span class="event-title">${title}</span><span class="event-meta">${meta}</span></div><span class="source">${source}</span></div>`).join('');
}

function drawChart() {
  const points = [56, 42, 61, 48, 74, 63, 91, 81, 105, 87, 119, 94, 112, 126, 96, 103, 82, 98, 89, 108, 76, 97, 71, 84];
  const width = 700, height = 190, max = 140;
  const line = points.map((p, i) => `${i ? 'L' : 'M'} ${(i * width / (points.length - 1)).toFixed(1)} ${(height - p / max * height).toFixed(1)}`).join(' ');
  document.querySelector('#linePath').setAttribute('d', line);
  document.querySelector('#areaPath').setAttribute('d', `${line} L ${width} ${height} L 0 ${height} Z`);
}

function showToast(message) { const toast = document.querySelector('#toast'); toast.textContent = message; toast.classList.add('show'); clearTimeout(window.toastTimer); window.toastTimer = setTimeout(() => toast.classList.remove('show'), 2500); }

document.querySelectorAll('#searchInput, #severityFilter, #statusFilter').forEach(el => el.addEventListener('input', renderAlerts));
document.querySelector('#refreshBtn').addEventListener('click', () => showToast('Telemetry refreshed successfully'));
document.querySelector('#newCaseBtn').addEventListener('click', () => showToast('New investigation case created'));
document.querySelector('#navAlertCount').textContent = alerts.filter(a => a.status !== 'resolved').length;
document.querySelector('#openAlerts').textContent = alerts.filter(a => a.status !== 'resolved').length;
document.querySelector('#criticalAlerts').textContent = alerts.filter(a => a.severity === 'critical' && a.status !== 'resolved').length;
document.querySelector('#eventCount').textContent = '24,891';
renderAlerts(); renderCoverage(); renderEvents(); drawChart();
