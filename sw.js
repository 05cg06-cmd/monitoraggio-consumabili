const CACHE_NAME = 'monitoraggio-app-v11';
const ASSETS_TO_PRECACHE = [
  './',
  './index.html',
  './app.js?v=11',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
  './initial_data.enc',
  'https://cdn.tailwindcss.com',
  'https://unpkg.com/lucide@latest',
  'https://cdn.sheetjs.com/xlsx-0.20.1/package/dist/xlsx.full.min.js'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_PRECACHE).catch((err) => {
        console.warn('Pre-cache parziale:', err);
      });
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
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
  self.clients.claim();
});

// Network-First con salvataggio automatico in Cache per funzionamento 100% Offline
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  if (e.request.url.includes('api.github.com')) return;

  e.respondWith(
    fetch(e.request)
      .then((response) => {
        if (response && (response.status === 200 || response.type === 'opaque')) {
          const respClone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(e.request, respClone);
          });
        }
        return response;
      })
      .catch(async () => {
        const cached = await caches.match(e.request);
        if (cached) return cached;
        const cachedIgnoreQuery = await caches.match(e.request, { ignoreSearch: true });
        if (cachedIgnoreQuery) return cachedIgnoreQuery;
        return caches.match('./index.html');
      })
  );
});
