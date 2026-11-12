import { next } from '@vercel/functions';

// Login Basic Auth. Username & password diambil dari Environment Variables Vercel:
// AUTH_USER dan AUTH_PASS (jangan ditulis di kode).
export const config = { matcher: '/(.*)' };

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export default function middleware(request) {
  const user = process.env.AUTH_USER;
  const pass = process.env.AUTH_PASS;

  // Kalau env belum diisi, tolak semua akses (aman secara default)
  if (user && pass) {
    const header = request.headers.get('authorization') || '';
    const [scheme, encoded] = header.split(' ');
    if (scheme === 'Basic' && encoded) {
      try {
        const decoded = atob(encoded);
        const i = decoded.indexOf(':');
        const u = decoded.slice(0, i);
        const p = decoded.slice(i + 1);
        if (safeEqual(u, user) && safeEqual(p, pass)) return next();
      } catch (e) {}
    }
  }

  return new Response('Perlu login.', {
    status: 401,
    headers: { 'WWW-Authenticate': 'Basic realm="Dashboard", charset="UTF-8"' },
  });
}
