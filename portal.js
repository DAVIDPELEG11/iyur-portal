// איור פרוייקטים – הפורטל ללקוחות: חיבור ל-Supabase, כניסה, זיהוי פנים (Passkey) ועזרים משותפים לכל הדפים.
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/+esm';
import { startRegistration, startAuthentication, browserSupportsWebAuthn } from 'https://cdn.jsdelivr.net/npm/@simplewebauthn/browser@11.0.0/+esm';
import { SUPABASE_URL, SUPABASE_ANON_KEY } from './config.js';

export const sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: true, detectSessionInUrl: true, flowType: 'implicit' } });
export const $ = (s) => document.querySelector(s);
export const here = (p) => new URL(p, location.href).href;
export function msg(el, text, kind = '') { el.textContent = text; el.className = 'msg ' + kind; }

async function fn(name, body, auth = false) {
  const headers = { 'Content-Type': 'application/json', apikey: SUPABASE_ANON_KEY };
  if (auth) { const { data } = await sb.auth.getSession(); if (data.session) headers.Authorization = 'Bearer ' + data.session.access_token; }
  const r = await fetch(`${SUPABASE_URL}/functions/v1/${name}`, { method: 'POST', headers, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || 'שגיאה'); return j;
}
export const canPasskey = () => browserSupportsWebAuthn();

// the device's face / fingerprint / Windows Hello becomes a key of this account (the user is signed in)
export async function addPasskey() {
  const { options, challengeId } = await fn('passkey', { action: 'register-options' }, true);
  const response = await startRegistration({ optionsJSON: options });
  await fn('passkey', { action: 'register-verify', challengeId, response, device: navigator.userAgent }, true);
}
// sign in with the device's key: the function verifies it and returns a one-time sign-in token, which becomes the session
export async function passkeyLogin() {
  const { options, challengeId } = await fn('passkey', { action: 'login-options' });
  const response = await startAuthentication({ optionsJSON: options });
  const { token_hash } = await fn('passkey', { action: 'login-verify', challengeId, response });
  const { error } = await sb.auth.verifyOtp({ token_hash, type: 'magiclink' }); if (error) throw error;
}
export const inviteCustomer = (email, project, remove = false, link = false) => fn('invite-customer', { email, project, remove, link }, true);

export async function needUser(adminOnly = false) {
  const { data } = await sb.auth.getSession();
  if (!data.session) { location.replace(here('index.html')); return null; }
  if (adminOnly) { const { data: a } = await sb.from('admins').select('user_id').eq('user_id', data.session.user.id).maybeSingle(); if (!a) { location.replace(here('projects.html')); return null; } }
  return data.session.user;
}
export async function isAdmin(uid) { const { data } = await sb.from('admins').select('user_id').eq('user_id', uid).maybeSingle(); return !!data; }
export async function signOut() { await sb.auth.signOut(); location.replace(here('index.html')); }

// stops a page's script for good without an error in the console (the page is leaving for another one)
export const halt = () => new Promise(() => {});
