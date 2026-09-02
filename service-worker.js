const CACHE = 'sentinelscope-v7';
const APP_SHELL = ['./', './index.html', './manifest.webmanifest', './assets/css/styles.css', './assets/css/professional.css', './assets/js/app.js', './assets/js/starter.js', './assets/js/supabase-config.js', './assets/js/supabase-client.js', './assets/icons/sentinel.svg'];
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  const requestUrl = new URL(event.request.url);
  const isAppAsset = requestUrl.origin === self.location.origin;
  event.respondWith(fetch(event.request).then(response => {
    if (isAppAsset && response.ok) caches.open(CACHE).then(cache => cache.put(event.request, response.clone()));
    return response;
  }).catch(() => caches.match(event.request).then(cached => cached || caches.match('./index.html'))));
});
