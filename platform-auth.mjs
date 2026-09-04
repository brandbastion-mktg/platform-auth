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

export const CLIENT_VERSION = '1.3.0';

// --- page permissions (1.2.0) -------------------------------------------------
//
// The platform can now say not only WHICH application somebody may open but
// which of its pages, and the answer rides in the handoff token and then in this
// application's own session. See the README's closed list: this module CARRIES
// those permissions and never interprets one. It does not know what a page is,
// which routes need which, or what any of the ids mean. The application owns all
// of that, because the application is the only thing that can.
//
// NULL MEANS EVERY PAGE, AND THAT IS THE WHOLE COMPATIBILITY STORY. A token or a
// session minted before 1.2.0 carries no page list at all, and the only safe
// reading of "no answer" is the behaviour of the day before this shipped:
// everything the person's application grant already allowed. An EMPTY ARRAY is a
// different statement - a person whose every page has been closed - and the two
// must never collapse into each other. Getting this backwards locks a whole team
// out of a whole tool on the deploy that introduces it, which is why the rule is
// in one exported function rather than re-implemented in each application.
export function allows(pages, pageId) {
  if (pages === null || pages === undefined) return true;
  if (!Array.isArray(pages)) return true;
  return pages.includes(String(pageId));
}

// --- the other tools a person holds (1.3.0) ------------------------------------
//
// The platform can also say WHICH OTHER APPLICATIONS this person may open, so
// that an application's tool menu can leave out the ones they cannot. Without
// this every application's menu was a fixed list of the whole fleet, and a
// colleague without a tool still saw its name in every sibling's menu
// (2026-09-03). The application could not filter even if it wanted to: nothing
// told it. The Hub already hides what a person cannot open, on the launcher and
// in its own header; this is the same rule carried into the tools.
//
// SAME SHAPE, SAME RULE AS PAGES, AND FOR THE SAME REASON. The list rides in the
// handoff token and then in this application's own session, unread by this
// module: it does not know what a tool is, which tools exist, or what any id
// means. NULL MEANS EVERY TOOL - a token or session from before 1.3.0 says
// nothing, and the only safe reading of nothing is the menu as it was the day
// before, which is the whole fleet. An EMPTY ARRAY is the real answer "no other
// tool at all", and the two never collapse. This is a menu, not a gate: the
// platform's own door refuses anyone without the grant whatever a menu shows.
export function holds(apps, appId) {
  if (apps === null || apps === undefined) return true;
  if (!Array.isArray(apps)) return true;
  return apps.includes(String(appId));
}

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
  function issue({ userId, email, pages = null, apps = null, now = Date.now() }) {
    const claims = {
      u: String(userId), e: String(email || ''), a: appId,
      exp: Math.floor(now / 1000) + sessionHours * 3600,
      n: randomBytes(6).toString('base64url'),
    };
    // Omitted rather than sent as null when there is nothing to say, so an
    // absent list stays absent through the whole round trip. See `allows`.
    if (Array.isArray(pages)) claims.p = pages.map(String);
    // The tools this person holds, same treatment (1.3.0). See `holds`.
    if (Array.isArray(apps)) claims.t = apps.map(String);
    const body = b64(JSON.stringify(claims));
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
      // `pages` is signed along with everything else, so an application can trust
      // it exactly as far as it trusts the identity beside it. null means every
      // page; see `allows`, which is the only correct way to ask.
      return {
        id: claims.u,
        email: claims.e,
        pages: Array.isArray(claims.p) ? claims.p.map(String) : null,
        // The tools this person holds, or null meaning every tool (1.3.0).
        // `holds` is the only correct way to ask.
        apps: Array.isArray(claims.t) ? claims.t.map(String) : null,
      };
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
    // The page list travels straight from the token into this application's own
    // session, unread. THIS IS THE ONLY MOMENT THE APPLICATION LEARNS IT: there
    // is no call back to the platform, so a permission changed after this point
    // lands when the session next renews, up to its twelve-hour life. That is the
    // same revocation lag already accepted for the application grant itself,
    // now true of a smaller and more casual action.
    // The tool list rides the same way (1.3.0): read once here, held for the
    // session, never asked for again.
    res.cookie(cookieName, issue({
      userId: claims.userId, email: claims.email, pages: claims.pages, apps: claims.apps,
    }), {
      ...cookieOptions(req), maxAge: sessionHours * 3600 * 1000,
    });
    res.setHeader('Cache-Control', 'no-store');
    res.redirect('/');
  }

  function signOut(req, res) {
    res.clearCookie(cookieName, cookieOptions(req));
    res.redirect(`${platformUrl.replace(/\/+$/, '')}/login`);
  }

  // `mayOpen` is `allows` bound to the current request, and it is the only piece
  // of 1.2.0 on this object. It answers "is this page in the set the platform
  // issued", nothing more: it does not know which routes need which page, and
  // never will - see the closed list.
  const mayOpen = (req, pageId) => allows(req?.user?.pages, pageId);

  return {
    attach, required, handoff, signOut, issue, read, mayOpen, appId, version: CLIENT_VERSION,
  };
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
    return {
      userId: claims.u,
      email: claims.e,
      appId: claims.a,
      // null when the token says nothing about pages, which means every page.
      // An empty array is the different, real answer of "no pages at all".
      pages: Array.isArray(claims.p) ? claims.p.map(String) : null,
      // Likewise for the tools this person holds (1.3.0): null means every tool.
      apps: Array.isArray(claims.t) ? claims.t.map(String) : null,
    };
  } catch {
    return null;
  }
}
