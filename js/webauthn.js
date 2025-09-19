// webauthn.js - optional biometric unlock with WebAuthn PRF extension
import { randomBytes, b64enc, b64dec } from './crypto.js';

const WEBAUTHN_META_KEY = 'webauthn-meta'; // {credIdB64, rpId, prfSaltB64, pubKeyJwk?}

function supported(){
  return !!(window.PublicKeyCredential && navigator.credentials);
}

async function createPasskey(){
  if(!supported()) throw new Error("WebAuthn not supported");
  const challenge = randomBytes(32);
  const userId = randomBytes(16);
  const rpId = location.hostname;
  const publicKey = {
    challenge,
    rp: { name: "Vaultie", id: rpId },
    user: { id: userId, name: "vaultie@local", displayName: "Vaultie Local User" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
    authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "preferred", userVerification: "required" },
    timeout: 60000,
    attestation: "none",
    extensions: { prf: true }
  };
  const cred = await navigator.credentials.create({ publicKey });
  const credId = new Uint8Array(cred.rawId);
  // Try to store the public key from attestation (none -> not available cross-browser); we rely on PRF for secret, not on verify
  const prfSalt = randomBytes(32);
  const meta = { credIdB64: b64enc(credId), rpId, prfSaltB64: b64enc(prfSalt) };
  return meta;
}

async function getPrfSecret(meta){
  // Request PRF eval
  const challenge = randomBytes(32); // dummy, we are offline
  const allow = [{ id: new Uint8Array(b64dec(meta.credIdB64)), type:'public-key' }];
  const publicKey = {
    challenge,
    allowCredentials: allow,
    userVerification: "required",
    timeout: 60000,
    extensions: { prf: { eval: { first: new Uint8Array(b64dec(meta.prfSaltB64)) } } }
  };
  const assertion = await navigator.credentials.get({ publicKey });
  const exts = assertion.getClientExtensionResults();
  if(!exts || !exts.prf || !exts.prf.results || !exts.prf.results.first){
    throw new Error("PRF not available from authenticator");
  }
  const secret = exts.prf.results.first; // ArrayBuffer
  return secret;
}

export { supported, createPasskey, getPrfSecret, WEBAUTHN_META_KEY };
