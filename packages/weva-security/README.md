# weva-security

WEVA, the **Weighted Endpoint & Velocity Algorithm** from our Student Information System thesis, packaged as drop-in Express middleware. A proof of concept: it runs and is tested, but it is not published to npm.

```
score = velocityIncrement × endpointWeight × failRateFactor × 5      (clamped to 0–100)
```

| Factor | What it measures |
|---|---|
| `velocityIncrement` | Requests per second above the client's own learned baseline; at least 2 while it has failed logins outstanding |
| `endpointWeight` | The route's blast radius: 1 routine, 2 authentication, 3 one-record writes, 4 whole-database operations |
| `failRateFactor` | 1 + 0.5 per failed login not yet settled by a successful one |

| Score | Verdict | Response |
|---|---|---|
| 0–24 | ALLOW | Your route runs |
| 25–59 | LOG | Your route runs; the evaluation is reported |
| 60–84 | THROTTLE | `429 Too Many Requests` with `Retry-After: 15` |
| 85–100 | BLOCK | `403 Forbidden`; the client is blocked for 60 s (`Retry-After` = seconds left) |

## Usage

```js
import express from 'express';
import { wevaSecurity } from 'weva-security';

const app = express();
app.use(express.json());              // before WEVA: it reads the login email from req.body
app.use(wevaSecurity({
  authPaths: ['/api/login'],          // password checks (weight 2)
  endpointWeights: {                  // other routes to guard
    '/api/students/:id': 3,
    '/api/admin/backup': 4
  }
}));

app.post('/api/login', async (req, res) => {
  // ...verify the password; on failure answer 401 as usual...
  req.weva.loginSucceeded(req.body.email);   // after a real sign-in: settles this client's failed attempts
  res.json({ success: true });
});
```

Only the listed routes are scored; static files and every other route pass through untouched. The thesis build gets the same effect by attaching WEVA route by route.

The client identifies itself with an application-layer device ID in the `x-device-id` header, a random ID kept per browser:

```js
const deviceId = localStorage.getItem('deviceId') ?? `DEV-${crypto.randomUUID().replaceAll('-', '')}`;
localStorage.setItem('deviceId', deviceId);
await fetch('/api/login', { method: 'POST', headers: { 'content-type': 'application/json', 'x-device-id': deviceId }, body });
```

A request without a valid device ID is identified by its IP alone. Behind a reverse proxy, set Express's `trust proxy` so that `req.ip` is the client's address, not the proxy's.

## What a password-guessing device sees

One wrong guess per second from one device (`examples/attack.js`):

| Guess | Failures outstanding | Formula | Score | Response |
|---|---|---|---|---|
| 1 | 0 | 0 × 2 × 1 × 5 | 0 | 401 from your route |
| 2 | 1 | 2 × 2 × 1.5 × 5 | 30 | 401 (LOG) |
| 3 | 2 | 2 × 2 × 2 × 5 | 40 | 401 (LOG) |
| 4 | 3 | 2 × 2 × 2.5 × 5 | 50 | 401 (LOG) |
| 5 | 4 | 2 × 2 × 3 × 5 | 60 | **429**, `Retry-After: 15` |
| 6–7 | 5–6 | 2 × 2 × 3.5–4 × 5 | 70–80 | 429 |
| 8 | 7 | 2 × 2 × 4.5 × 5 | 90 | **403**, blocked 60 s |

A script is caught sooner: three requests in the same millisecond read as 2000 req/s, so the third scores 100 and is blocked. A bot that sends a new device ID with every guess has no device history, but all its guesses land on one IP, and the IP layer throttles the 5th one inside 30 seconds.

## Try it

```
npm test              # everything: behavior over real HTTP, formula parity with core/scorer.js, the production replay
npm run test:parity   # only the replay: the same traffic through middleware/securityMiddleware.js and this package
npm run example       # terminal 1: examples/server.js on http://localhost:4000
npm run attack        # terminal 2: 8 wrong passwords, then the right one, from one device
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `authPaths` | `[]` | Route patterns where a POST (any method but GET, HEAD or OPTIONS) is a credential check. Weight 2 unless listed in `endpointWeights`. |
| `endpointWeights` | `{}` | Other routes to score, pattern → weight. Patterns use `:param` segments and match case-insensitively. |
| `thresholds` | `{ suspicious: 25, critical: 60, block: 85 }` | Where LOG, THROTTLE and BLOCK start. |
| `throttleRetryAfterSeconds` | `15` | `Retry-After` on a 429. |
| `blockMs` | `60000` | How long a BLOCK lasts. |
| `windowMs` | `30000` | Window for velocity and for the IP's recent attempts. |
| `deviceIdHeader` | `'x-device-id'` | Header carrying the device ID: letters, digits, `_` and `-`, up to 45 characters. |
| `getTargetAccount` | `req => req.body?.email ?? req.body?.username` | The account a login attempt targets. |
| `onEvaluation` | logs LOG, THROTTLE and BLOCK | Receives every evaluation (identities, score, verdict, formula), e.g. for an audit log or SIEM. |
| `blockStore` | in memory | Any object with async `findStatus(id)`, `block(id, until)` and `clear(id)`, such as Redis, to share blocks between servers. |
| `minVelocityFloor`, `failRateIncrement`, `velocityPointScale`, `emaAlpha` | `2`, `0.5`, `5`, `0.1` | Formula tuning, as in the thesis build. |

On a listed route, `req.weva` holds the request's `score`, `decision` and `breakdown`, and `loginSucceeded(account)`.

## Scope

Kept from the thesis build (`core/` and `middleware/securityMiddleware.js`): the formula and its tuning; the device and IP identities, with the higher score deciding; failed attempts settled per account; baselines learned only from traffic that was let through; an IP window that counts only attempts that reached the password check; a block placed only on the identity that earned it. `test/production-parity.js` replays a dozen attack and traffic scenarios through the thesis build's middleware and through this package, and requires the same outcome for every request: deciding identity, formula, score, verdict, HTTP status and retry time.

Changed or left out:

- **Retry-After header.** The SDK sets the standard header. The thesis build sends `retryAfter: 15` in the JSON body only; the SDK sends that too.
- **Route matching.** The thesis build reads the Express route that matched. Under `app.use()` none has matched yet, so the SDK matches the path against the listed patterns itself.
- **Not included:** the signed-in-account identity, the admin +15 threshold tolerance, the database audit trail, the admin IP whitelist and the OTP step.
- **One process.** Request history and baselines live in memory, as in the thesis build; only the block store can be shared.

Limits carried over from the thesis build:

- **No time decay.** A device's failed attempts clear only when it signs in successfully or after 30 idle minutes. `Retry-After` says when to ask again, not that the next attempt will pass: a device with 4 failures is throttled again however long it waits, and since a refused attempt never reaches the password check, it cannot clear them.
- A client without a device ID is keyed by its IP, so its block covers every client behind that IP.
- Everyone behind one IP shares its 30-second attempt window: four failed logins from that address throttle the next login from it until they age out.
- Several requests from one device within a fraction of a second read as automation. List the routes people use one request at a time (logins, writes, exports), not routes a page calls in parallel.
