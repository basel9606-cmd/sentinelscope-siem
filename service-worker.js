const CACHE = 'sentinelscope-v3';
const APP_SHELL = ['./', './index.html', './manifest.webmanifest', './assets/css/styles.css', './assets/css/professional.css', './assets/js/app.js', './assets/js/starter.js', './assets/js/supabase-config.js', './assets/js/supabase-client.js', './assets/icons/sentinel.svg'];
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  event.respondWith(caches.match(event.request).then(cached => cached || fetch(event.request).then(response => {
    const copy = response.clone();
    if (new URL(event.request.url).origin === self.location.origin) caches.open(CACHE).then(cache => cache.put(event.request, copy));
    return response;
  }).catch(() => caches.match('./index.html'))));
});
