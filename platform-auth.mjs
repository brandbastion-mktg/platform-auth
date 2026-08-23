// platform-auth: how an applet learns who just arrived from the sign-in platform.
//
// A small, dependency-free module for a set of internal applications that share
// one sign-in. The platform signs a short-lived handoff token; this module
// verifies it and starts a session that belongs to the receiving applet alone.
// It never calls the platform at runtime, so the platform is not a live
// dependency of every application that trusts it.
//
// THIS REPOSITORY IS THE CANONICAL SOURCE. Applications depend on a tagged
// version of it rather than keeping a copy. See README.md, which also carries
// the closed list of what is allowed to live in this file.
//
// Node standard library only, so an application can adopt it without taking on
// a single dependency of its own.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const CLIENT_VERSION = '1.1.0';

const SESSION_HOURS = 12;
const b64 = (v) => Buffer.from(v).toString('base64url');

function need(value, name) {
  if (!value) throw new Error(`platformAuth: ${name} is required.`);
  return value;
}

// Constant-time compare that also refuses a length mismatch and an empty value,
// so "" can never match "".
function same(a, b) {
  try {
    const x = Buffer.from(String(a || ''));
    const y = Buffer.from(String(b || ''));
    if (!x.length || x.length !== y.length) return false;
    return timingSafeEqual(x, y);
  } catch {
    return false;
  }
}

// Cookies without a parser dependency.
function readCookie(req, name) {
  const header = req.headers?.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) {
      try { return decodeURIComponent(part.slice(eq + 1).trim()); } catch { return null; }
    }
  }
  return null;
}

export function platformAuth({ appId, secret, platformUrl, cookieName, sessionHours = SESSION_HOURS } = {}) {
  need(appId, 'appId');
  need(cookieName, 'cookieName');
  need(platformUrl, 'platformUrl');
  if (!secret || String(secret).length < 32) {
    // FAIL CLOSED AND LOUD. A short or missing secret must never fall back to
    // signing with nothing: that produces sessions anybody can forge while
    // everything looks like it is working.
    throw new Error('platformAuth: secret is missing or too short (needs 32+ chars).');
  }

  const sign = (value) => createHmac('sha256', String(secret)).update(value).digest('base64url');

  // --- this applet's own session -------------------------------------------
  // Self-contained and signed, NOT looked up: the client never calls the
  // platform at runtime (see README). Revocation therefore lands when this
  // expires, which is the accepted trade.
  function issue({ userId, email, now = Date.now() }) {
    const body = b64(JSON.stringify({
      u: String(userId), e: String(email || ''), a: appId,
      exp: Math.floor(now / 1000) + sessionHours * 3600,
      n: randomBytes(6).toString('base64url'),
    }));
    return `${body}.${sign(body)}`;
  }

  function read(value, { now = Date.now() } = {}) {
    try {
      if (!value) return null;
      const [body, sig] = String(value).split('.');
      if (!body || !sig || !same(sign(body), sig)) return null;
      const claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      // Bound to THIS applet: a session minted for another one is not valid here
      // even though the secret is shared.
      if (claims.a !== appId) return null;
      if (!claims.exp || claims.exp * 1000 <= now) return null;
      return { id: claims.u, email: claims.e };
    } catch {
      return null;
    }
  }

  const cookieOptions = (req) => {
    const https = req.secure || req.get?.('x-forwarded-proto') === 'https';
    return { httpOnly: true, sameSite: 'lax', secure: Boolean(https), path: '/' };
  };

  // --- the middleware -------------------------------------------------------

  // Attaches req.user when there is a valid session. Never refuses: a public
  // route needs to know who you are without being blocked.
  function attach(req, _res, next) {
    req.user = read(readCookie(req, cookieName));
    next();
  }

  // The gate. Fails closed, including when a check throws.
  function required(req, res, next) {
    try {
      if (req.user) return next();
      if (!req.user && readCookie(req, cookieName)) res.clearCookie(cookieName, cookieOptions(req));
    } catch { /* fall through to the refusal */ }
    if (req.accepts?.('html')) {
      // `next` names THIS applet's door on the platform, not the platform's
      // home. The platform honours it on both paths (already signed in, and
      // after a fresh sign-in), so a lapsed session costs a round trip rather
      // than a second choice from the launcher (1.1.0; it used to say '/').
      const back = `${platformUrl.replace(/\/+$/, '')}/login?next=${encodeURIComponent(`/go/${appId}`)}`;
      return res.redirect(back);
    }
    return res.status(401).json({ error: 'Sign in on the platform first.' });
  }

  // Where the platform sends people. Verifies the token, starts this applet's
  // own session, then REDIRECTS TO A CLEAN URL so the token does not sit in
  // browser history or in an access log. An applet that skipped that redirect
  // would undo most of what the sixty-second lifetime is for.
  function handoff(req, res) {
    const token = String(req.query?.token || '');
    const claims = verifyHandoff(token, appId, secret);
    if (!claims) {
      // A refusal with a door, not a dead end (1.1.0): the token has a
      // sixty-second life, so anyone who hits this has nothing to act on but
      // this page. The link goes through the platform's own /go route, which
      // re-checks the grant and mints a fresh token.
      const again = `${platformUrl.replace(/\/+$/, '')}/go/${encodeURIComponent(appId)}`;
      return res.status(401).type('html').send(
        '<p style="font:15px/1.6 system-ui;max-width:36em;margin:15vh auto 0;padding:0 24px">'
        + 'That sign-in link is not valid any more. '
        + `<a href="${again}">Open this tool from the platform again.</a></p>`,
      );
    }
    res.cookie(cookieName, issue({ userId: claims.userId, email: claims.email }), {
      ...cookieOptions(req), maxAge: sessionHours * 3600 * 1000,
    });
    res.setHeader('Cache-Control', 'no-store');
    res.redirect('/');
  }

  function signOut(req, res) {
    res.clearCookie(cookieName, cookieOptions(req));
    res.redirect(`${platformUrl.replace(/\/+$/, '')}/login`);
  }

  return { attach, required, handoff, signOut, issue, read, appId, version: CLIENT_VERSION };
}

// Verify a handoff token minted by the platform. Kept as a standalone export so
// it can be tested, and read, without constructing the whole middleware.
//
// `expectedApp` is a REQUIRED argument rather than an option, deliberately: a
// token minted for one applet opening another is the most valuable forgery
// available here, and this is the shape that stops it being omitted silently.
export function verifyHandoff(token, expectedApp, secret, { now = Date.now() } = {}) {
  try {
    if (!token || !expectedApp || !secret) return null;
    const [body, signature] = String(token).split('.');
    if (!body || !signature) return null;
    const expected = createHmac('sha256', String(secret)).update(body).digest('base64url');
    if (!same(expected, signature)) return null;
    const claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (claims.a !== String(expectedApp)) return null;
    if (!claims.exp || claims.exp * 1000 <= now) return null;
    return { userId: claims.u, email: claims.e, appId: claims.a };
  } catch {
    return null;
  }
}
