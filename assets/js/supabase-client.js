(function initialiseSentinelScopeAuth() {
  const config = window.SentinelScopeConfig;
  if (!config || !window.supabase) return;
  const client = window.supabase.createClient(config.supabaseUrl, config.publishableKey);
  window.SentinelScope = { client, configured: true, session: null };
  const authButton = document.querySelector('#authBtn');
  const analystBadge = document.querySelector('.analyst');
  const authDialog = document.querySelector('#authDialog');
  const authForm = document.querySelector('#authForm');
  const authEmail = document.querySelector('#authEmail');
  const authMessage = document.querySelector('#authMessage');
  function setSignedOut() { window.SentinelScope.session = null; authButton.textContent = 'Sign in'; analystBadge.textContent = '—'; analystBadge.title = 'Sign in to access protected cases'; }
  function setSignedIn(session) { const email = session.user.email || 'Analyst'; window.SentinelScope.session = session; authButton.textContent = 'Sign out'; analystBadge.textContent = email.slice(0, 2).toUpperCase(); analystBadge.title = `Signed in as ${email}`; }
  async function refreshSession() { const { data } = await client.auth.getSession(); data.session ? setSignedIn(data.session) : setSignedOut(); return data.session; }
  authButton.addEventListener('click', async () => {
    if (window.SentinelScope.session) { await client.auth.signOut(); showToast('Signed out of SentinelScope'); return; }
    authMessage.textContent = ''; authMessage.className = 'auth-message'; authDialog.hidden = false; authEmail.focus();
  });

  document.querySelector('#authCancel').addEventListener('click', () => { authDialog.hidden = true; });
  document.querySelector('#githubSignIn').addEventListener('click', async () => {
    const { error } = await client.auth.signInWithOAuth({ provider: 'github', options: { redirectTo: `${window.location.origin}${window.location.pathname}` } });
    if (error) { authMessage.textContent = `GitHub sign-in error: ${error.message}`; authMessage.className = 'auth-message error'; }
  });
  authForm.addEventListener('submit', async event => {
    event.preventDefault();
    const { error } = await client.auth.signInWithOtp({ email: authEmail.value.trim(), options: { emailRedirectTo: `${window.location.origin}${window.location.pathname}` } });
    authMessage.textContent = error ? `Sign-in error: ${error.message}` : 'Secure link sent. Check your inbox.';
    authMessage.className = `auth-message ${error ? 'error' : 'success'}`;
    if (!error) authForm.reset();
  });
  client.auth.onAuthStateChange((_event, session) => { session ? setSignedIn(session) : setSignedOut(); window.dispatchEvent(new CustomEvent('sentinelscope:session-changed', { detail: session })); });
  refreshSession();
})();
