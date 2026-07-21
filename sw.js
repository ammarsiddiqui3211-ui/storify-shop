const CACHE_NAME = 'storify-cache-v8';
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/images/logo/header.png',
  '/images/logo/footer.png',
  '/images/favicon/favicon.png',
  '/images/icon/Icon-v6.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS);
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    })
  );
});

self.addEventListener('fetch', (event) => {
  // Only intercept GET requests for local assets
  if (event.request.method !== 'GET') return;
  
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  const isHtml = url.pathname === '/' || url.pathname === '/index.html';

  if (isHtml) {
    // Network-First strategy for HTML (fresh content when online, fallback to cache when offline)
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          // If valid response, update the cache
          if (response.status === 200) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseClone);
            });
          }
          return response;
        })
        .catch(() => {
          // Network failed, retrieve from cache
          return caches.match(event.request);
        })
    );
  } else {
    // Cache-First strategy for images/assets
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        return fetch(event.request).then((response) => {
          if (response.status === 200) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseClone);
            });
          }
          return response;
        });
      })
    );
  }
});
