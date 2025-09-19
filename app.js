// app.js - PassVault core
const $ = (sel) => document.querySelector(sel);

// UI elements
const scrOnboarding = $("#screen-onboarding");
const scrLock = $("#screen-lock");
const scrApp = $("#screen-app");
const msgOnboarding = $("#onboarding-msg");
const msgLock = $("#lock-msg");

// IndexedDB
const DB_NAME = "passvault-db";
const DB_STORE = "kv";
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(DB_STORE)) db.createObjectStore(DB_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function dbGet(key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readonly");
    const st = tx.objectStore(DB_STORE);
    const req = st.get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function dbSet(key, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readwrite");
    const st = tx.objectStore(DB_STORE);
    const req = st.put(value, key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// Crypto helpers
const enc = new TextEncoder();
const dec = new TextDecoder();

function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64url(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = str.length % 4 ? 4 - (str.length % 4) : 0;
  str += "=".repeat(pad);
  const bin = atob(str);
  return new Uint8Array([...bin].map(c => c.charCodeAt(0)));
}
async function randomBytes(len=32) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}
async function pbkdf2Key(pin, salt, iterations=150000) {
  const keyMat = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    keyMat,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function aesEncrypt(key, data) {
  const iv = await randomBytes(12);
  const pt = typeof data === "string" ? enc.encode(data) : data;
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);
  return { iv: b64url(iv), ct: b64url(new Uint8Array(ct)) };
}
async function aesDecrypt(key, ivB64, ctB64) {
  const iv = fromB64url(ivB64);
  const ct = fromB64url(ctB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}
async function exportRawKey(key) {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return jwk.k;
}
async function importAesKeyFromJwkK(k) {
  return crypto.subtle.importKey("jwk", { kty: "oct", k, alg: "A256GCM", ext: true, k }, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// State
const state = { unlocked:false, masterKey:null, vault:[], requireBio:false, credId:null };

// Meta
const getMeta = () => dbGet("meta");
const setMeta = (m) => dbSet("meta", m);
const getWrappedKey = () => dbGet("wrappedKey");
const setWrappedKey = (o) => dbSet("wrappedKey", o);
async function saveVault() {
  if (!state.masterKey) throw new Error("Vault not unlocked");
  const payload = JSON.stringify({ entries: state.vault });
  const { iv, ct } = await aesEncrypt(state.masterKey, payload);
  await dbSet("vault", { iv, ct, v:1 });
}
async function loadVault() {
  const blob = await dbGet("vault");
  if (!blob) { state.vault = []; return; }
  const pt = await aesDecrypt(state.masterKey, blob.iv, blob.ct);
  const obj = JSON.parse(dec.decode(pt));
  state.vault = obj.entries || [];
}

// WebAuthn
function isWebAuthnAvailable(){ return !!(window.PublicKeyCredential && navigator.credentials); }
async function createPlatformCredential() {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const pubKey = {
    challenge,
    rp: { name: "PassVault" },
    user: { id: userId, name: "passvault-user", displayName: "PassVault User" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    timeout: 60000,
    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
    attestation: "none"
  };
  const cred = await navigator.credentials.create({ publicKey: pubKey });
  return b64url(new Uint8Array(cred.rawId));
}
async function requestUserVerification(credIdB64url) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const allowCreds = credIdB64url ? [{ type: "public-key", id: fromB64url(credIdB64url), transports: ["internal"] }] : [];
  const pubKey = { challenge, timeout: 60000, userVerification:"required", allowCredentials: allowCreds };
  await navigator.credentials.get({ publicKey: pubKey });
  return true;
}

// Setup
async function handleSetup() {
  msgOnboarding.textContent = "";
  const pin = document.querySelector("#setup-pin").value.trim();
  const enableBio = document.querySelector("#setup-bio").checked;
  if (pin.length < 4) { msgOnboarding.textContent = "PIN must be at least 4 characters."; return; }
  try {
    const mk = await crypto.subtle.generateKey({ name:"AES-GCM", length:256 }, true, ["encrypt","decrypt"]);
    const mkJwkK = await exportRawKey(mk);
    const salt = await randomBytes(16);
    const wrapKey = await pbkdf2Key(pin, salt);
    const encMK = await aesEncrypt(wrapKey, new TextEncoder().encode(mkJwkK));

    let credId = null;
    if (enableBio && isWebAuthnAvailable()) {
      try { credId = await createPlatformCredential(); } catch(_) {}
    }
    await setWrappedKey({ salt: b64url(salt), iv: encMK.iv, ct: encMK.ct, algo: "AES-GCM", pbkdf2:{ iter:150000, hash:"SHA-256" } });
    await setMeta({ requireBio: !!credId, credId, createdAt: Date.now(), v:1 });

    state.masterKey = mk;
    state.unlocked = true;
    state.requireBio = !!credId;
    state.credId = credId;
    await saveVault();
    await loadVault();
    showApp();
  } catch (e) {
    msgOnboarding.textContent = "Setup failed: " + e.message;
  }
}

// Unlock
async function handleUnlock() {
  msgLock.textContent = "";
  const pin = document.querySelector("#unlock-pin").value.trim();
  if (!pin) { msgLock.textContent = "Enter your PIN."; return; }
  try {
    const meta = await getMeta();
    if (!meta) throw new Error("Not set up yet.");
    if (meta.requireBio) {
      try { await requestUserVerification(meta.credId); }
      catch { msgLock.textContent = "Biometric verification failed or cancelled."; return; }
    }
    const wrap = await getWrappedKey();
    const salt = fromB64url(wrap.salt);
    const wrapKey = await pbkdf2Key(pin, salt, wrap.pbkdf2?.iter || 150000);
    const mkJwkKBytes = await aesDecrypt(wrapKey, wrap.iv, wrap.ct);
    const mkJwkK = new TextDecoder().decode(mkJwkKBytes);
    const mk = await importAesKeyFromJwkK(mkJwkK);

    state.masterKey = mk;
    state.unlocked = true;
    state.requireBio = !!meta.requireBio;
    state.credId = meta.credId || null;
    await loadVault();
    showApp();
  } catch (e) {
    msgLock.textContent = "Unlock failed. Check your PIN.";
  }
}

// Lock
function doLock(){ state.unlocked=false; state.masterKey=null; state.vault=[]; document.querySelector("#unlock-pin").value=""; showLock(); }

// Entries
function uid(){ return crypto.randomUUID(); }
function nowISO(){ return new Date().toISOString(); }
function renderList(filter=""){
  const list = document.querySelector("#list");
  list.innerHTML = "";
  const q = filter.toLowerCase();
  const entries = state.vault
    .filter(e => !q || e.app.toLowerCase().includes(q) || e.username.toLowerCase().includes(q))
    .sort((a,b) => (b.updatedAt||b.createdAt||"").localeCompare(a.updatedAt||a.createdAt||""));
  for (const e of entries) {
    const card = document.createElement("div");
    card.className = "p-3 border rounded-2xl flex gap-3 items-start";
    card.innerHTML = \`
      <div class="grow">
        <div class="font-medium">\${e.app}</div>
        <div class="text-xs text-slate-500 break-all">\${e.url || ""}</div>
        <div class="mt-1 text-sm"><span class="text-slate-500">User:</span> \${e.username}</div>
        <div class="mt-1 flex gap-2">
          <button class="btn bg-slate-100" data-act="copy-user" data-id="\${e.id}">Copy user</button>
          <button class="btn bg-slate-100" data-act="copy-pass" data-id="\${e.id}">Copy pass</button>
          <button class="btn bg-slate-100" data-act="open" data-id="\${e.id}">Open</button>
          <button class="btn bg-sky-600 text-white" data-act="edit" data-id="\${e.id}">Edit</button>
          <button class="btn bg-rose-600 text-white" data-act="del" data-id="\${e.id}">Delete</button>
        </div>
      </div>\`;
    list.appendChild(card);
  }
}
async function copyToClipboard(text){ try{ await navigator.clipboard.writeText(text); }catch{ alert("Clipboard blocked by browser permissions."); } }
function openEntry(ev){
  const id = ev.target.dataset.id;
  const item = state.vault.find(x=>x.id===id);
  if(!item) return;
  document.querySelector("#dlg-title").textContent="Edit Entry";
  document.querySelector("#f-id").value=item.id;
  document.querySelector("#f-app").value=item.app;
  document.querySelector("#f-url").value=item.url||"";
  document.querySelector("#f-username").value=item.username;
  document.querySelector("#f-password").value=item.password;
  document.querySelector("#dlg").showModal();
}
function newEntry(){
  document.querySelector("#dlg-title").textContent="Add Entry";
  document.querySelector("#f-id").value="";
  document.querySelector("#f-app").value="";
  document.querySelector("#f-url").value="";
  document.querySelector("#f-username").value="";
  document.querySelector("#f-password").value="";
  document.querySelector("#dlg").showModal();
}
async function saveEntry(){
  const id = document.querySelector("#f-id").value || uid();
  const entry = {
    id,
    app: document.querySelector("#f-app").value.trim(),
    url: document.querySelector("#f-url").value.trim(),
    username: document.querySelector("#f-username").value.trim(),
    password: document.querySelector("#f-password").value,
    createdAt: document.querySelector("#f-id").value ? undefined : nowISO(),
    updatedAt: nowISO()
  };
  if (!entry.app || !entry.username) { alert("App/Site and Username are required."); return; }
  const idx = state.vault.findIndex(x=>x.id===id);
  if (idx>=0) state.vault[idx] = { ...state.vault[idx], ...entry };
  else state.vault.push(entry);
  await saveVault();
  document.querySelector("#dlg").close();
  renderList(document.querySelector("#search").value);
}
async function deleteEntry(id){
  if (!confirm("Delete this entry?")) return;
  const idx = state.vault.findIndex(x=>x.id===id);
  if (idx>=0){ state.vault.splice(idx,1); await saveVault(); renderList(document.querySelector("#search").value); }
}

// Generator
function randInt(max){ return crypto.getRandomValues(new Uint32Array(1))[0] % max; }
function pick(chars){ return chars[randInt(chars.length)]; }
function generatePassword(opts){
  const lower="abcdefghijklmnopqrstuvwxyz", upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ", nums="0123456789", syms="!@#$%^&*()_-+=[]{};:,.?/|`~";
  let pool="", must=[];
  if(opts.lower){ pool+=lower; must.push(pick(lower)); }
  if(opts.upper){ pool+=upper; must.push(pick(upper)); }
  if(opts.num){ pool+=nums; must.push(pick(nums)); }
  if(opts.sym){ pool+=syms; must.push(pick(syms)); }
  if(!pool) pool = lower+upper+nums;
  const len = Math.max(8, Math.min(64, opts.length||20));
  let out = must.join("");
  while(out.length < len) out += pick(pool);
  const a = out.split("");
  for(let i=a.length-1;i>0;i--){ const j=randInt(i+1); [a[i],a[j]]=[a[j],a[i]]; }
  return a.join("");
}

// Export/Import (fix)
async function exportBackup(){
  if(!state.unlocked) return alert("Unlock first.");
  const pass = prompt("Set a backup password (store it safely):");
  if(!pass) return;
  const salt = await crypto.getRandomValues(new Uint8Array(16));
  const key = await pbkdf2Key(pass, salt, 200000);
  const payload = JSON.stringify({ meta: await getMeta(), data: state.vault });
  const { iv, ct } = await aesEncrypt(key, payload);
  const blob = new Blob([JSON.stringify({ v:1, salt: b64url(salt), iv, ct })], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `passvault-backup-${new Date().toISOString().slice(0,10)}.vault`;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
async function importBackupFile(file){
  try{
    const obj = JSON.parse(await file.text());
    if(!obj || !obj.salt || !obj.iv || !obj.ct) throw new Error("Invalid file");
    const pass = prompt("Enter backup password:");
    if(!pass) return;
    const key = await pbkdf2Key(pass, fromB64url(obj.salt), 200000);
    const pt = await aesDecrypt(key, obj.iv, obj.ct); // FIXED
    const payload = JSON.parse(new TextDecoder().decode(pt));
    // Disable biometrics on import; user can recreate credential on this device by resetting
    await setMeta({ ...(payload.meta||{}), requireBio:false, credId:null });
    state.requireBio = false; state.credId = null;
    state.vault = payload.data || [];
    await saveVault();
    alert("Import complete. Biometrics are disabled after restore; set up again if desired.");
    renderList(document.querySelector("#search").value);
  }catch(e){ alert("Import failed: " + e.message); }
}

// Screens
async function decideScreen(){ const meta = await getMeta(); if(!meta) showOnboarding(); else showLock(); }
function showOnboarding(){ scrOnboarding.classList.remove("hidden"); scrLock.classList.add("hidden"); scrApp.classList.add("hidden"); }
function showLock(){ scrOnboarding.classList.add("hidden"); scrLock.classList.remove("hidden"); scrApp.classList.add("hidden"); }
function showApp(){ scrOnboarding.classList.add("hidden"); scrLock.classList.add("hidden"); scrApp.classList.remove("hidden"); renderList(document.querySelector("#search").value); }

// Wire up
document.querySelector("#btn-setup").addEventListener("click", handleSetup);
document.querySelector("#btn-import-first").addEventListener("click", () => document.querySelector("#file-import").click());
document.querySelector("#btn-unlock").addEventListener("click", handleUnlock);
document.querySelector("#btn-bio").addEventListener("click", async () => {
  try{
    const meta = await getMeta();
    if(!meta?.credId){ alert("Biometrics not enabled. You can reset vault to enable it, or keep using PIN."); return; }
    await requestUserVerification(meta.credId);
    alert("Biometric check passed. Now enter PIN to decrypt.");
  }catch{ alert("Biometric failed or cancelled."); }
});
document.querySelector("#btn-lock").addEventListener("click", doLock);
document.querySelector("#btn-add").addEventListener("click", newEntry);
document.querySelector("#save").addEventListener("click", (e)=>{ e.preventDefault(); saveEntry(); });
document.querySelector("#gen").addEventListener("click", () => {
  const opts = {
    lower: document.querySelector("#g-lower").checked,
    upper: document.querySelector("#g-upper").checked,
    num: document.querySelector("#g-num").checked,
    sym: document.querySelector("#g-sym").checked,
    length: parseInt(document.querySelector("#g-len").value, 10) || 20
  };
  document.querySelector("#f-password").value = generatePassword(opts);
});
document.querySelector("#g-len").addEventListener("input", () => document.querySelector("#g-len-val").textContent=document.querySelector("#g-len").value);
document.querySelector("#search").addEventListener("input", (e)=>renderList(e.target.value));
document.querySelector("#file-import").addEventListener("change", async (e)=>{ const f=e.target.files?.[0]; if(f) await importBackupFile(f); e.target.value=""; });
document.querySelector("#btn-export").addEventListener("click", exportBackup);
document.querySelector("#list").addEventListener("click", async (e) => {
  const act = e.target.dataset.act, id = e.target.dataset.id;
  if(!act) return;
  const item = state.vault.find(x=>x.id===id);
  if(act==="copy-user") await copyToClipboard(item.username);
  if(act==="copy-pass") await copyToClipboard(item.password);
  if(act==="edit") openEntry(e);
  if(act==="del") await deleteEntry(id);
  if(act==="open" && item.url) window.open(item.url, "_blank", "noopener,noreferrer");
});

// Bootstrap
decideScreen();
