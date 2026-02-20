var CACHE_VERSION = 'SW_VERSION_PLACEHOLDER';
var CACHE_NAME = 'dnstool-' + CACHE_VERSION;

var IMMUTABLE_ASSETS = [
  '/static/css/bootstrap-dark-theme.min.css',
  '/static/css/fontawesome-subset.min.css',
  '/static/js/bootstrap.bundle.min.js',
  '/static/webfonts/fa-solid-900.woff2',
  '/static/favicon.svg'
];

globalThis.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(IMMUTABLE_ASSETS);
    })
  );
  globalThis.skipWaiting();
});

globalThis.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(names) {
      return Promise.all(
        names.filter(function(name) { return name !== CACHE_NAME; })
             .map(function(name) { return caches.delete(name); })
      );
    })
  );
  event.waitUntil(globalThis.clients.claim());
});

globalThis.addEventListener('fetch', function(event) {
  var url = new URL(event.request.url);

  if (!url.pathname.startsWith('/static/')) {
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
    return;
  }

  var isVersioned = url.search.indexOf('v=') !== -1;

  if (isVersioned) {
    event.respondWith(
      fetch(event.request).then(function(response) {
        if (response.ok) {
          var clone = response.clone();
          caches.open(CACHE_NAME).then(function(cache) {
            cache.put(event.request, clone);
          });
        }
        return response;
      }).catch(function() {
        return caches.match(event.request);
      })
    );
  } else {
    event.respondWith(
      caches.match(event.request).then(function(cached) {
        if (cached) return cached;
        return fetch(event.request).then(function(response) {
          if (response.ok) {
            var clone = response.clone();
            caches.open(CACHE_NAME).then(function(cache) {
              cache.put(event.request, clone);
            });
          }
          return response;
        });
      })
    );
  }
});
