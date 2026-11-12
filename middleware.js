import { next } from '@vercel/functions';

// Login dengan halaman sendiri (login.html) + cookie sesi bertanda tangan (HMAC).
// Env wajib: AUTH_USER, AUTH_PASS. Env opsional tapi disarankan: AUTH_SECRET (teks acak panjang).
export const config = { matcher: '/(.*)' };

const COOKIE = 'sa_session';
const enc = new TextEncoder();

const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function sign(msg, secret) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function readCookie(req) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|; )' + COOKIE + '=([^;]*)'));
  return m ? m[1] : '';
}

const setCookie = (value, maxAge) =>
  `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax` + (maxAge === undefined ? '' : `; Max-Age=${maxAge}`);

const go = (req, path, extra = {}) =>
  new Response(null, {
    status: 302,
    headers: { Location: new URL(path, req.url).toString(), 'Cache-Control': 'no-store', ...extra },
  });

export default async function middleware(request) {
  const user = process.env.AUTH_USER;
  const pass = process.env.AUTH_PASS;
  if (!user || !pass) {
    return new Response('Login belum dikonfigurasi: isi AUTH_USER dan AUTH_PASS di Vercel.', { status: 500 });
  }
  const secret = process.env.AUTH_SECRET || pass + '|' + user;
  const path = new URL(request.url).pathname;

  if (path === '/logout') return go(request, '/login', { 'Set-Cookie': setCookie('', 0) });

  if (path === '/login' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const okU = safeEqual(String(body.u || ''), user);
    const okP = safeEqual(String(body.p || ''), pass);
    if (okU && okP) {
      const exp = String(Date.now() + (body.r ? 30 * 864e5 : 12 * 36e5));
      const value = exp + '.' + (await sign(exp, secret));
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Set-Cookie': setCookie(value, body.r ? 2592000 : undefined) },
      });
    }
    await new Promise((r) => setTimeout(r, 800));
    return new Response(JSON.stringify({ ok: false }), { status: 401, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  }

  let valid = false;
  const [exp, sig] = readCookie(request).split('.');
  if (exp && sig && Number(exp) > Date.now()) valid = safeEqual(sig, await sign(exp, secret));

  if (path === '/login' || path === '/login.html') return valid ? go(request, '/') : next();
  return valid ? next() : go(request, '/login');
}
