// service-worker.js - cache assets for offline use
const CACHE = 'vaultie-cache-v1';
const ASSETS = [
  './',
  './index.html',
  './js/app.js',
  './js/crypto.js',
  './js/db.js',
  './js/webauthn.js',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png'
];

self.addEventListener('install', (e)=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)));
});

self.addEventListener('activate', (e)=>{
  e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));
});

self.addEventListener('fetch', (e)=>{
  const url = new URL(e.request.url);
  if (ASSETS.includes(url.pathname.replace(/\/+/g,'/').replace(/.*\//,'.'))) {
    e.respondWith(caches.match(e.request).then(r=> r || fetch(e.request)));
    return;
  }
  e.respondWith(
    caches.match(e.request).then(response => response || fetch(e.request).then(res => {
      // Optionally: cache GET navigations
      return res;
    }).catch(()=> response))
  );
});
