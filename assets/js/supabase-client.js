(function initialiseSentinelScopeAuth() {
  const config = window.SentinelScopeConfig;
  if (!config || !window.supabase) return;
  const client = window.supabase.createClient(config.supabaseUrl, config.publishableKey);
  window.SentinelScope = { client, configured: true, session: null };
  const authButton = document.querySelector('#authBtn');
  const analystBadge = document.querySelector('.analyst');
  function setSignedOut() { window.SentinelScope.session = null; authButton.textContent = 'Sign in'; analystBadge.textContent = '—'; analystBadge.title = 'Sign in to access protected cases'; }
  function setSignedIn(session) { const email = session.user.email || 'Analyst'; window.SentinelScope.session = session; authButton.textContent = 'Sign out'; analystBadge.textContent = email.slice(0, 2).toUpperCase(); analystBadge.title = `Signed in as ${email}`; }
  async function refreshSession() { const { data } = await client.auth.getSession(); data.session ? setSignedIn(data.session) : setSignedOut(); return data.session; }
  authButton.addEventListener('click', async () => {
    if (window.SentinelScope.session) { await client.auth.signOut(); showToast('Signed out of SentinelScope'); return; }
    const email = window.prompt('Enter your analyst email for a secure sign-in link:');
    if (!email) return;
    const { error } = await client.auth.signInWithOtp({ email, options: { emailRedirectTo: `${window.location.origin}${window.location.pathname}` } });
    showToast(error ? `Sign-in error: ${error.message}` : 'Secure sign-in link sent. Check your email.');
  });
  client.auth.onAuthStateChange((_event, session) => { session ? setSignedIn(session) : setSignedOut(); window.dispatchEvent(new CustomEvent('sentinelscope:session-changed', { detail: session })); });
  refreshSession();
})();
