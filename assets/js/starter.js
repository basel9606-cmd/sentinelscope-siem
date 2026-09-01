const starterCases = [];

function showStarterToast(message) {
  const toast = document.querySelector('#toast'); toast.textContent = message; toast.classList.add('show');
  clearTimeout(window.starterToastTimer); window.starterToastTimer = setTimeout(() => toast.classList.remove('show'), 2600);
}

function renderCases() {
  document.querySelector('#caseRows').innerHTML = starterCases.map(c => `<tr><td><span class="alert-name">${c.id}</span><span class="alert-sub">${c.title}</span></td><td><span class="severity ${c.priority}">${c.priority}</span></td><td>${c.owner}</td><td>${c.next_step}</td><td class="case-sla">${c.sla}</td><td><span class="status ${c.status}">${c.status}</span></td></tr>`).join('');
  const active = starterCases.filter(c => c.status !== 'resolved' && c.status !== 'closed').length;
  document.querySelector('#caseCount').textContent = active; document.querySelector('#activeCaseMetric').textContent = active;
}

async function loadCases() {
  try {
    const supabase = window.SentinelScope?.client;
    if (supabase && window.SentinelScope.session) {
      const { data, error } = await supabase.from('cases').select('id, case_number, title, severity, status, next_step, opened_at, owner:profiles!cases_owner_id_fkey(display_name)').order('opened_at', { ascending: false });
      if (error) throw error;
      starterCases.splice(0, starterCases.length, ...data.map(item => ({ id: item.case_number, title: item.title, priority: item.severity, owner: item.owner?.display_name || 'Unassigned', next_step: item.next_step || 'Triage investigation', sla: '—', status: item.status })));
      renderCases(); return;
    }
    const response = await fetch('/api/cases');
    if (!response.ok) throw new Error('API unavailable');
    const data = await response.json(); starterCases.splice(0, starterCases.length, ...data.cases); renderCases();
  } catch {
    starterCases.splice(0, starterCases.length,
      { id: 'INC-2026-081', title: 'Potential endpoint compromise', priority: 'critical', owner: 'Alex Morgan', next_step: 'Validate C2 connection', sla: '00:18:42', status: 'investigating' },
      { id: 'INC-2026-079', title: 'Impossible travel sign-in', priority: 'high', owner: 'Maya Chen', next_step: 'Confirm user activity', sla: '01:07:25', status: 'investigating' });
    renderCases();
  }
}

async function createCase() {
  try {
    const supabase = window.SentinelScope?.client;
    if (supabase && window.SentinelScope.session) {
      const caseNumber = `INC-${new Date().getFullYear()}-${Math.floor(100 + Math.random() * 900)}`;
      const { data: created, error } = await supabase.from('cases').insert({ case_number: caseNumber, title: 'New analyst investigation', severity: 'medium', status: 'new', owner_id: window.SentinelScope.session.user.id, next_step: 'Triage investigation' }).select().single();
      if (error) {
        if (error.code === '42501') throw new Error('Case creation requires Analyst access.');
        throw error;
      }
      starterCases.unshift({ id: created.case_number, title: created.title, priority: created.severity, owner: 'Unassigned', next_step: created.next_step, sla: '—', status: created.status });
      renderCases(); showStarterToast(`${created.case_number} created in Supabase`); return;
    }
    const response = await fetch('/api/cases', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: 'New analyst investigation', severity: 'medium' }) });
    if (!response.ok) throw new Error('Create failed');
    const { case: created } = await response.json(); starterCases.unshift(created); renderCases(); showStarterToast(`${created.id} created and assigned to Alex Morgan`);
  } catch (error) { showStarterToast(error.message || 'Unable to save the case.'); }
  document.querySelector('#cases').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

document.querySelector('#createCaseBtn').addEventListener('click', createCase);
document.querySelector('#newCaseBtn').addEventListener('click', event => { event.stopImmediatePropagation(); createCase(); }, true);
window.addEventListener('sentinelscope:session-changed', loadCases);
loadCases();
