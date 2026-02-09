const CACHE_NAME = 'dnstool-v1';
const STATIC_ASSETS = [
  '/static/css/bootstrap-dark-theme.min.css',
  '/static/css/custom.min.css',
  '/static/css/fontawesome-subset.min.css',
  '/static/js/bootstrap.bundle.min.js',
  '/static/webfonts/fa-solid-900.woff2',
  '/static/favicon.svg'
];

self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(STATIC_ASSETS);
    })
  );
  globalThis.skipWaiting();
});

self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(names) {
      return Promise.all(
        names.filter(function(name) { return name !== CACHE_NAME; })
             .map(function(name) { return caches.delete(name); })
      );
    })
  );
  event.waitUntil(clients.claim());
});

self.addEventListener('fetch', function(event) {
  const url = new URL(event.request.url);
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(event.request).then(function(cached) {
        if (cached) return cached;
        return fetch(event.request).then(function(response) {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(function(cache) {
              cache.put(event.request, clone);
            });
          }
          return response;
        });
      })
    );
  } else {
    event.respondWith(
      fetch(event.request).catch(function() {
        if (event.request.mode === 'navigate') {
          return new Response(
            '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline - DNS Tool</title><style>body{background:#212529;color:#dee2e6;font-family:-apple-system,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center}h1{font-size:1.5rem}p{color:#adb5bd}</style></head><body><div><h1>You are offline</h1><p>DNS Tool requires an internet connection to perform domain analysis.</p><p>Please check your connection and try again.</p></div></body></html>',
            {headers: {'Content-Type': 'text/html'}}
          );
        }
      })
    );
  }
});
