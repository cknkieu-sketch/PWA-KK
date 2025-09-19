// app.js - main UI logic
import { enc, dec, b64enc, b64dec, deriveKeyFromPassword, encryptWithKey, decryptWithKey, importAesKeyRaw, randomBytes, generatePassword } from './crypto.js';
import { dbGet, dbSet, dbDel } from './db.js';
import { supported as webauthnSupported, createPasskey, getPrfSecret, WEBAUTHN_META_KEY } from './webauthn.js';

const VAULT_KEY = 'vaultie-data'; // stores the encrypted bundle
const STATE = {
  unlocked: false,
  vaultKey: null, // CryptoKey for AES-GCM
  entries: [], // decrypted entries
};

function qs(id){ return document.getElementById(id); }
function show(id){ document.getElementById(id).classList.remove('hidden'); }
function hide(id){ document.getElementById(id).classList.add('hidden'); }

function nowIso(){ return new Date().toISOString(); }

async function haveVault(){
  const v = await dbGet(VAULT_KEY);
  return !!v;
}

function sanitize(str){ return (str||"").toString(); }

async function renderEntries(){
  const list = qs('entries');
  const q = qs('search').value.trim().toLowerCase();
  list.innerHTML = "";
  STATE.entries
    .filter(e => !q || (e.name?.toLowerCase().includes(q) || e.url?.toLowerCase().includes(q) || e.user?.toLowerCase().includes(q)))
    .forEach((e, idx) => {
      const card = document.createElement('div');
      card.className = 'entry';
      card.innerHTML = `
        <div class="row">
          <strong>${e.name ? sanitize(e.name) : '(no name)'}</strong>
          <div class="row" style="gap:6px;">
            <button data-edit="${idx}" class="ghost">Edit</button>
            <button data-del="${idx}" class="warn">Delete</button>
          </div>
        </div>
        <small class="muted">${e.url ? `<a href="${e.url}" target="_blank" rel="noopener">${e.url}</a>` : ''}</small>
        <div class="row">
          <input value="${sanitize(e.user||'')}" readonly>
          <button data-copyu="${idx}" class="ghost">Copy</button>
        </div>
        <div class="row">
          <input type="password" value="${sanitize(e.pass||'')}" readonly data-pass="${idx}">
          <button data-toggle="${idx}" class="ghost">Show</button>
          <button data-copyp="${idx}" class="ghost">Copy</button>
        </div>
      `;
      list.appendChild(card);
    });

  // Wire buttons
  list.querySelectorAll('button').forEach(btn => {
    if(btn.dataset.edit){ btn.onclick = ()=> editEntry(parseInt(btn.dataset.edit)); }
    if(btn.dataset.del){ btn.onclick = ()=> delEntry(parseInt(btn.dataset.del)); }
    if(btn.dataset.copyu){ btn.onclick = ()=> copyText(STATE.entries[parseInt(btn.dataset.copyu)].user||""); }
    if(btn.dataset.copyp){ btn.onclick = ()=> copyText(STATE.entries[parseInt(btn.dataset.copyp)].pass||""); }
    if(btn.dataset.toggle){
      btn.onclick = ()=>{
        const i = parseInt(btn.dataset.toggle);
        const input = list.querySelector(`[data-pass="${i}"]`);
        if(input.type==='password'){ input.type='text'; btn.textContent='Hide'; } else { input.type='password'; btn.textContent='Show'; }
      };
    }
  });
}

function copyText(txt){
  navigator.clipboard?.writeText(txt);
}

function editEntry(idx){
  const e = idx>=0 ? STATE.entries[idx] : { name:"", url:"", user:"", pass:"" };
  const name = prompt("Application name", e.name||"");
  if(name===null) return;
  const url = prompt("URL (optional)", e.url||"");
  if(url===null) return;
  const user = prompt("Username / ID", e.user||"");
  if(user===null) return;
  const pass = prompt("Password (leave blank to keep)", "");
  if(idx>=0){
    STATE.entries[idx] = { name, url, user, pass: pass ? pass : e.pass };
  }else{
    STATE.entries.push({ name, url, user, pass });
  }
  persist();
  renderEntries();
}

function delEntry(idx){
  if(confirm("Delete this entry?")){
    STATE.entries.splice(idx,1);
    persist();
    renderEntries();
  }
}

async function persist(){
  // Encrypt entries JSON with STATE.vaultKey
  const bytes = enc.encode(JSON.stringify(STATE.entries));
  const {iv, ct} = await encryptWithKey(STATE.vaultKey, bytes);
  const bundle = await dbGet(VAULT_KEY) || {};
  bundle.vault = { algo: 'AES-GCM', iv: b64enc(iv), ciphertext: b64enc(ct) };
  bundle.updatedAt = nowIso();
  await dbSet(VAULT_KEY, bundle);
}

async function createVaultFromMasterPassword(password){
  if(!password || password.length<8) throw new Error("Master Password must be at least 8 characters.");
  // Generate a random data encryption key (DEK)
  const rawDek = randomBytes(32).buffer;
  const dekKey = await importAesKeyRaw(rawDek);

  // Wrap DEK with MP key
  const salt = randomBytes(16);
  const iter = 250000;
  const mpKey = await deriveKeyFromPassword(password, salt, iter);
  const wrap1 = await encryptWithKey(mpKey, rawDek);
  const wrappedMp = { algo:'AES-GCM', salt: b64enc(salt), iterations: iter, iv: b64enc(wrap1.iv), wrapped: b64enc(wrap1.ct) };

  // Try to create a passkey & PRF KEK
  let wrappedBio = null;
  try{
    const meta = await createPasskey();
    const prfSecret = await getPrfSecret(meta); // ArrayBuffer (user verification required)
    const bioKey = await importAesKeyRaw(prfSecret);
    const wrapB = await encryptWithKey(bioKey, rawDek);
    wrappedBio = { algo:'AES-GCM', credIdB64: meta.credIdB64, rpId: meta.rpId, saltB64: meta.prfSaltB64, iv: b64enc(wrapB.iv), wrapped: b64enc(wrapB.ct) };
    await dbSet(WEBAUTHN_META_KEY, {credIdB64: meta.credIdB64, prfSaltB64: meta.prfSaltB64, rpId: meta.rpId});
  }catch(e){
    console.warn("Biometric setup skipped or not supported:", e.message);
  }

  const bundle = {
    version: 1,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    wrappedKeys: { mp: wrappedMp, bio: wrappedBio },
    vault: { algo:'AES-GCM', iv: b64enc(randomBytes(12)), ciphertext: b64enc(new Uint8Array()) } // placeholder empty
  };
  await dbSet(VAULT_KEY, bundle);

  STATE.vaultKey = dekKey;
  STATE.entries = [];
  STATE.unlocked = true;
}

async function unlockWithMasterPassword(password){
  const bundle = await dbGet(VAULT_KEY);
  if(!bundle || !bundle.wrappedKeys?.mp) throw new Error("No vault found.");
  const salt = new Uint8Array(b64dec(bundle.wrappedKeys.mp.salt));
  const iter = bundle.wrappedKeys.mp.iterations || 250000;
  const mpKey = await deriveKeyFromPassword(password, salt, iter);
  const iv = b64dec(bundle.wrappedKeys.mp.iv);
  const wrapped = b64dec(bundle.wrappedKeys.mp.wrapped);
  const rawDek = await decryptWithKey(mpKey, iv, wrapped);
  STATE.rawDek = rawDek; // keep for this session to allow enabling biometrics
  STATE.vaultKey = await importAesKeyRaw(rawDek);
  await loadEntries();
}

async function unlockWithBiometrics(){
  const bundle = await dbGet(VAULT_KEY);
  if(!bundle || !bundle.wrappedKeys?.bio) throw new Error("Biometric unlock not set up on this device.");
  const meta = await dbGet(WEBAUTHN_META_KEY);
  if(!webauthnSupported()) throw new Error("Biometric (WebAuthn) not supported.");

  const prfSecret = await getPrfSecret(meta);
  const bioKey = await importAesKeyRaw(prfSecret);
  const iv = b64dec(bundle.wrappedKeys.bio.iv);
  const wrapped = b64dec(bundle.wrappedKeys.bio.wrapped);
  const rawDek = await decryptWithKey(bioKey, iv, wrapped);
  STATE.vaultKey = await importAesKeyRaw(rawDek);
  await loadEntries();
}

async function loadEntries(){
  const bundle = await dbGet(VAULT_KEY);
  if(!bundle || !bundle.vault) throw new Error("Vault not found");
  const {iv, ciphertext} = bundle.vault;
  if(ciphertext && b64dec(ciphertext).byteLength>0){
    const bytes = await decryptWithKey(STATE.vaultKey, b64dec(iv), b64dec(ciphertext));
    STATE.entries = JSON.parse(dec.decode(bytes));
  }else{
    STATE.entries = [];
  }
  STATE.unlocked = true;
  hide('onboarding'); hide('unlock'); show('vaultUI');
  await renderEntries();
}

async function exportBackup(){
  const bundle = await dbGet(VAULT_KEY);
  if(!bundle) throw new Error("Nothing to export");
  const blob = new Blob([JSON.stringify(bundle, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download = 'vaultie-backup.json'; a.click();
  setTimeout(()=> URL.revokeObjectURL(url), 2000);
}

async function importBackup(file){
  const text = await file.text();
  const bundle = JSON.parse(text);
  if(!bundle?.wrappedKeys?.mp) throw new Error("Invalid backup file");
  await dbSet(VAULT_KEY, bundle);
  alert("Backup imported. Use your existing Master Password (or biometrics if previously set on this device) to unlock.");
  location.reload();
}

function wireUI(){
  qs('setupBtn').onclick = async ()=>{
    try{
      await createVaultFromMasterPassword(qs('mpw').value);
      hide('onboarding'); show('vaultUI');
      await renderEntries();
    }catch(e){ alert(e.message); }
  };
  qs('registerBioBtn').onclick = async ()=>{
    try{
      // If vault exists, add biometric wrapping to it using current DEK derived from MP first
      if(await haveVault()){
        const bundle = await dbGet(VAULT_KEY);
        // Require MP to unwrap DEK
        const mpw = prompt("To enable biometrics, enter your Master Password:");
        await unlockWithMasterPassword(mpw);
        // Create passkey & PRF, wrap DEK
        const meta = await createPasskey();
        const prfSecret = await getPrfSecret(meta);
        const bioKey = await importAesKeyRaw(prfSecret);
        const rawDek = STATE.rawDek; if(!rawDek) throw new Error('Please unlock with Master Password first, then enable biometrics again.');
        const rawDek = await decryptWithKey(STATE.vaultKey, new Uint8Array(12).buffer, new Uint8Array().buffer).catch(()=>null);
        const wrapB = await encryptWithKey(bioKey, rawDek);
        bundle.wrappedKeys.bio = { algo:'AES-GCM', credIdB64: meta.credIdB64, rpId: meta.rpId, saltB64: meta.prfSaltB64, iv: b64enc(wrapB.iv), wrapped: b64enc(wrapB.ct) };
        await dbSet(VAULT_KEY, bundle);
        await dbSet(WEBAUTHN_META_KEY, {credIdB64: meta.credIdB64, prfSaltB64: meta.prfSaltB64, rpId: meta.rpId});
        alert('Biometric unlock enabled on this device.');
      } else {
        // Create full new vault with biometric in one go
        await createVaultFromMasterPassword(qs('mpw').value || prompt("Create a Master Password (min 8 chars)"));
        alert("Biometric setup attempted during vault creation. If your device supports PRF, biometric-only unlock is enabled.");
      }
    }catch(e){ alert(e.message); }
  };

  qs('unlockBtn').onclick = async ()=>{
    try{
      await unlockWithMasterPassword(qs('unlockMpw').value);
    }catch(e){ qs('unlockMsg').textContent = e.message; }
  };
  qs('unlockBioBtn').onclick = async ()=>{
    try{
      await unlockWithBiometrics();
    }catch(e){ qs('unlockMsg').textContent = e.message; }
  };

  qs('addEntryBtn').onclick = ()=> editEntry(-1);
  qs('lockBtn').onclick = ()=>{ STATE.unlocked=false; STATE.entries=[]; STATE.vaultKey=null; hide('vaultUI'); show('unlock'); };
  qs('search').oninput = ()=> renderEntries();
  qs('exportBtn').onclick = ()=> exportBackup();
  qs('importFile').onchange = (e)=> importBackup(e.target.files[0]);

  // Generator UI
  qs('genBtn').onclick = ()=>{
    try{
      const pwd = generatePassword({
        length: parseInt(qs('genLen').value,10)||16,
        lower: qs('optLower').checked,
        upper: qs('optUpper').checked,
        nums: qs('optNums').checked,
        syms: qs('optSyms').checked
      });
      qs('genOut').value = pwd;
    }catch(e){ alert(e.message); }
  };
  qs('copyGenBtn').onclick = ()=> copyText(qs('genOut').value);
}

async function init(){
  wireUI();
  if(await haveVault()){
    hide('onboarding'); show('unlock');
  }else{
    show('onboarding');
    if(!webauthnSupported()){
      document.getElementById('registerBioBtn').classList.add('hidden');
    }
  }
}

init();
