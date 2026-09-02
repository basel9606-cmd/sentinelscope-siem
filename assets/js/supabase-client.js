(function initialiseSentinelScopeAuth() {
  const config = window.SentinelScopeConfig;
  if (!config || !window.supabase) return;
  const client = window.supabase.createClient(config.supabaseUrl, config.publishableKey);
  window.SentinelScope = { client, configured: true, session: null, profile: null };
  const authButton = document.querySelector('#authBtn');
  const analystBadge = document.querySelector('.analyst');
  const authDialog = document.querySelector('#authDialog');
  const authForm = document.querySelector('#authForm');
  const authEmail = document.querySelector('#authEmail');
  const authMessage = document.querySelector('#authMessage');
  const authRedirectUrl = `${window.location.origin}${window.location.pathname}`;

  function clearAuthHash() {
    if (window.location.hash.includes('access_token') || window.location.hash.includes('error=')) {
      window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.search}`);
    }
  }

  function setSignedOut() {
    window.SentinelScope.session = null;
    window.SentinelScope.profile = null;
    authButton.textContent = 'Sign in';
    analystBadge.textContent = '—';
    analystBadge.title = 'Sign in to access protected cases';
  }

  async function setSignedIn(session) {
    const email = session.user.email || 'Analyst';
    window.SentinelScope.session = session;
    authButton.textContent = 'Sign out';
    analystBadge.textContent = email.slice(0, 2).toUpperCase();
    analystBadge.title = `Signed in as ${email}`;
    clearAuthHash();

    const { data } = await client.rpc('current_soc_profile');
    window.SentinelScope.profile = data?.[0] || { display_name: email, role: 'viewer' };
    analystBadge.title = `${window.SentinelScope.profile.display_name} · ${window.SentinelScope.profile.role}`;
  }

  async function applySession(session) {
    if (session) await setSignedIn(session); else setSignedOut();
    window.dispatchEvent(new CustomEvent('sentinelscope:session-changed', { detail: session }));
  }

  async function refreshSession() {
    const { data } = await client.auth.getSession();
    await applySession(data.session);
    return data.session;
  }
  authButton.addEventListener('click', async () => {
    if (window.SentinelScope.session) { await client.auth.signOut(); showToast('Signed out of SentinelScope'); return; }
    authMessage.textContent = ''; authMessage.className = 'auth-message'; authDialog.hidden = false; authEmail.focus();
  });

  document.querySelector('#authCancel').addEventListener('click', () => { authDialog.hidden = true; });
  document.querySelector('#githubSignIn').addEventListener('click', async () => {
    const { error } = await client.auth.signInWithOAuth({ provider: 'github', options: { redirectTo: authRedirectUrl } });
    if (error) { authMessage.textContent = `GitHub sign-in error: ${error.message}`; authMessage.className = 'auth-message error'; }
  });
  authForm.addEventListener('submit', async event => {
    event.preventDefault();
    const { error } = await client.auth.signInWithOtp({ email: authEmail.value.trim(), options: { emailRedirectTo: authRedirectUrl } });
    authMessage.textContent = error ? `Sign-in error: ${error.message}` : 'Secure link sent. Check your inbox.';
    authMessage.className = `auth-message ${error ? 'error' : 'success'}`;
    if (!error) authForm.reset();
  });
  client.auth.onAuthStateChange((_event, session) => { window.setTimeout(() => applySession(session), 0); });
  refreshSession();
})();
