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
    "@brandbastion-mktg/platform-auth": "https://github.com/brandbastion-mktg/platform-auth/archive/refs/tags/v1.2.0.tar.gz"
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

### Pages inside the application (1.2.0)

The platform can say which of an application's pages a person may open. The ids
are the application's own words for its screens; the platform stores them, ships
them, and never interprets one.

```js
app.get('/settings', (req, res, next) => (auth.mayOpen(req, 'settings')
  ? next()
  : res.redirect('/')));            // refuse on the route, never only in the menu
```

Two rules that are not optional:

- **Hiding a link is not a gate.** Leave the tab out of the navigation *and*
  refuse on the route, because anyone can type an address.
- **`null` means every page.** A session minted before 1.2.0 carries no list, and
  `allows`/`mayOpen` read that as everything. Never test `req.user.pages`
  directly: `[]` is a real answer meaning no pages at all, and the two look alike
  to a careless check.

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
4. **Carrying the opaque set of page permissions the platform issued alongside
   the identity, and answering whether a given id is in it.** Added in 1.2.0.

Never allowed:

- Anything one application needs and the others do not.
- Any business logic, any data access, any UI.
- Any knowledge of what an application does with a person once it knows who they
  are. A per-user quota is the worked example: it means nothing to the other
  applications and it stays in the one that has it.
- **Deciding which pages exist, what any page id means, or which routes need
  which permission.** That is the application's, always.
- Any network call.

### Why item 4 was added, since this list was written not to grow

**Decided 2026-08-30, deliberately and on the record.** The platform gained a
second level of access: it can now say not only which application somebody may
open but which of its pages. The module had to carry that or the design would
have had to break a bigger rule than this one.

The alternative was an application asking the platform "which pages may this
person see" on each request, which is the live dependency this whole design
exists to avoid, and a far worse trade for a navigation tab than it already was
for a login. So the answer rides in the token that already carries the identity,
and this module carries it the same way it carries an email address: **it moves
the value and never reads it.** The one function it gained, `allows`, is a set
membership test plus the null-means-everything rule, and that rule is here rather
than in each application precisely because getting it backwards locks a whole
team out of a whole tool on the deploy that introduces it.

The test of whether this was accretion: the module still does not know what a
page is. It cannot name one, cannot list them, and cannot say which route needs
which. If a later version can do any of those, the list has genuinely been broken.

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
