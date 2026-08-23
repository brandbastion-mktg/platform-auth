# platform-auth

The module an application imports so that somebody who signed in on a central
sign-in platform arrives already signed in here.

One file, no dependencies, Node standard library only. It verifies a short-lived
signed handoff token and starts a session that belongs to the receiving
application alone.

## Install

It is not published to a registry. Depend on a tagged version by URL:

```json
{
  "dependencies": {
    "@brandbastion-mktg/platform-auth": "https://github.com/brandbastion-mktg/platform-auth/archive/refs/tags/v1.1.0.tar.gz"
  }
}
```

A download URL rather than a `github:` reference on purpose: `github:` makes npm
shell out to `git`, which is absent from slim container images, so the dependency
resolves on a laptop and fails inside the build.

## Use

```js
import { platformAuth } from '@brandbastion-mktg/platform-auth';

const auth = platformAuth({
  appId: 'reports',                            // must match the platform's id for this app
  secret: process.env.PLATFORM_SECRET,         // the platform's signing secret
  platformUrl: process.env.PLATFORM_URL,       // where an unauthenticated visitor is sent
  cookieName: 'reports_session',               // THIS application's own cookie name
});

app.get('/auth/handoff', auth.handoff);  // consumes the token, then redirects to a clean URL
app.post('/auth/signout', auth.signOut);
app.use(auth.required);                  // everything below this line needs a session
```

Public routes go **above** `auth.required`: the application decides what is
public and the module never hears about it.

`platformAuth()` returns Express-shaped middleware. An application that does not
use Express can import `verifyHandoff` on its own and do its own cookie and
redirect glue; that is the framework-agnostic half and it is supported.

### Configuration

| Name | What it is |
|---|---|
| `PLATFORM_SECRET` | The platform's signing secret, shared with it. 32 characters or more, or the module refuses to start. |
| `PLATFORM_URL` | Where an unauthenticated visitor is sent. Config rather than a hardcoded address, so moving the platform is a settings change. |

## What is allowed to live in this file

**This list is closed.** The predicted failure mode of a shared sign-in module is
that it quietly accretes until it is a merged codebase with none of the benefits
of having chosen one. Every addition looks reasonable on its own, so the guard is
that the list was written before the first line and does not grow without a
deliberate, recorded decision.

Allowed:

1. Verifying a handoff token from the platform.
2. Creating, reading and clearing **this application's own** session cookie.
3. Deciding whether the current request is signed in, and sending it to the
   platform when it is not.

Never allowed:

- Anything one application needs and the others do not.
- Any business logic, any data access, any UI.
- Any knowledge of what an application does with a person once it knows who they
  are. A per-user quota is the worked example: it means nothing to the other
  applications and it stays in the one that has it.
- Any network call.

## Why it never calls the platform

An application that asked the platform "is this person still allowed in?" on
every request would make the platform a live dependency of every application,
which is the single point of failure this design exists to avoid. Instead the
handoff token is signed, and each application holds its own short session.

**The accepted cost is revocation lag.** Removing somebody centrally does not
close an application they already have open. Sessions last twelve hours, so
access ends within the working day. An application that needs instant revocation
should say so out loud rather than quietly adding a call back.

## Security notes

- The handoff token is **signed, not encrypted.** Anyone holding one can read the
  user id and email inside it. That is accepted for internal tools over https
  with a sixty-second token life.
- A session is **bound to the application it was minted for**, so a session or a
  handoff for one application cannot open another even though the secret is
  shared. That check is what makes sharing the secret safe.
- `verifyHandoff(token, expectedApp, secret)` takes the expected application as a
  **required argument** rather than an option, deliberately: a token minted for
  one application opening another is the most valuable forgery available here,
  and this shape is what stops the check being omitted silently.
- Nothing secret lives in this repository. The security is in the secret, which
  is held by each deployment and never appears here.

## Versioning

Tagged, and applications name the exact version they run. Upgrading is a
deliberate commit in each application rather than something that happens
underneath it.

## Licence

MIT. See [LICENSE](LICENSE).
