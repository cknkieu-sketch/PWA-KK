// crypto.js - encryption, key derivation, password generator, base64 utils

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64enc(buf){
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64dec(b64){
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) buf[i]=bin.charCodeAt(i);
  return buf.buffer;
}

async function deriveKeyFromPassword(password, salt, iterations=250000){
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations, hash:'SHA-256'},
    keyMat,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
}

async function encryptWithKey(key, dataBytes){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, dataBytes);
  return { iv: iv.buffer, ct };
}

async function decryptWithKey(key, iv, ct){
  return crypto.subtle.decrypt({name:'AES-GCM', iv:new Uint8Array(iv)}, key, ct);
}

async function importAesKeyRaw(raw){
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt','decrypt']);
}

function randomBytes(len){ const b = new Uint8Array(len); crypto.getRandomValues(b); return b; }

// Password generator: ensure at least one char of each selected class
function generatePassword(opts){
  const {length=16, lower=true, upper=true, nums=true, syms=true} = opts;
  const lowers = "abcdefghijklmnopqrstuvwxyz";
  const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const numbers = "0123456789";
  const symbols = "!@#$%^&*()-_=+[]{};:,.?/~`|";
  let pool = "";
  const required = [];
  if(lower){ pool += lowers; required.push(lowers); }
  if(upper){ pool += uppers; required.push(uppers); }
  if(nums){ pool += numbers; required.push(numbers); }
  if(syms){ pool += symbols; required.push(symbols); }
  if(pool.length===0) throw new Error("Select at least one character class.");
  const out = [];
  // ensure one of each selected
  required.forEach(set => out.push(set[Math.floor(Math.random()*set.length)]));
  // fill rest
  while(out.length < length){
    const ch = pool[Math.floor(Math.random()*pool.length)];
    out.push(ch);
  }
  // shuffle
  for(let i=out.length-1;i>0;i--){
    const j = Math.floor(Math.random()*(i+1)); [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join("").slice(0, length);
}

export { enc, dec, b64enc, b64dec, deriveKeyFromPassword, encryptWithKey, decryptWithKey, importAesKeyRaw, randomBytes, generatePassword };
