# @imqueue/http-protect

Implements simple HTTP traffic protection middleware for node-based express-like 
web-servers to detect and block abnormal activity on a server from a detected
IP sources.

Simple configuration allows to set desired limit on number of requests per given
time period and define the blacklist threshold for the users which are by 
exceeding the limit continue to send requests to the server.

The service protected by this module may be configured on a code level or by
setting environment variables.

## Requirements

- redis server

## Installation

```bash
npm i @imqueue/http-protect
```

## Usage

```typescript
import HttpProtect from '@imqueue/http-protect';

app.use(new HttpProtect().jsonMiddleware());
```

Or it is possible to do manual injection:

```typescript
import HttpProtect, { VerificationStatus } from '@imqueue/http-protect';

// inside some async function in the code
const protect = new HttpProtect();
const { status, httpCode } = await protect.verify(req);

switch (status) {
    case VerificationStatus.LIMITED: {
        // user us reached request limit, but not blacklisted yet.
        // warn about abnormal usage
        break;
    }
    case VerificationStatus.BANNED: {
        // bad traffic source, requests must be banned
        break;
    }
    default: {
        // good request, safe to go
        break;
    }
}
```

This module aldo provides simple API to check if given IP is blacklisted or not,
or get the list of banned network addresses:

All three are `async`, so they must be awaited — without `await`,
`bannedNetworks()` throws (`.toJSON` is not a function on a `Promise`) and the
other two log a pending `Promise` rather than a boolean:

```typescript
import HttpProtect from '@imqueue/http-protect';

const protect = new HttpProtect();

// get the list of banned networks
console.log((await protect.bannedNetworks()).toJSON());

// check if given IP is currently banned or not
console.log(await protect.isBanned('127.0.0.1'));

// check if given IP is currently limited or not
console.log(await protect.isLimited('127.0.0.1'));
```

This module uses redis server to deal with requests counters and banned 
networks. It also based on ioredis module to connect to redis server, so
you might want to configure it via constructor options or bypass existing
ioredis instance in the options. Please, refer `HttpProtectOptions` interface
for more details.

### Before you deploy it

Three properties of the defaults are worth deciding about deliberately.

**A ban does not expire.** Banned addresses go into a redis set that is never
given a TTL, and nothing in this module removes a member from it. Once an
address passes `banLimit` it is answered 418 until something outside this
module deletes it from `<redisPrefix>:block-list`. Plan for how you will lift
one — an admin endpoint, a cron, or a manual `SREM` — before you rely on the
ban threshold.

**`maxRequests` counts a continuous stream, not a fixed window.** The per-IP
counter's TTL is pushed back to `ttl` on *every* request from that address, so
the count is discarded only after a full `ttl` of silence. With the defaults,
200 requests in 10 seconds trips the limit — and so does one request per second
for 200 seconds, which is ordinary behaviour for a real user. If your sessions
are long-lived and chatty, raise `maxRequests` and `banLimit` accordingly, or
you will ban real users.

**Anything unidentifiable is refused.** If the resolver cannot produce an
address, that request is answered 429 without being counted, rather than served
unchecked. It is deliberately not pooled under a shared key, because one such
client could then exhaust that counter and get every other unidentifiable
client permanently banned.

`bannedNetworks()` and `isBanned()` widen every banned address to a `/32`,
which is right for IPv4 and wrong for IPv6 — a `/32` IPv6 prefix spans 2^96
addresses, so those two methods over-report for IPv6 clients. Actual blocking
is unaffected: `verify()` matches exact addresses in redis and does not use
them.

### Client IP resolution

By default the client IP is resolved with [request-ip](
https://www.npmjs.com/package/request-ip), which reads the usual proxy
headers (`x-forwarded-for`, `x-real-ip`, etc.). Because bans and rate limits
are keyed by this address, a client behind an untrusted proxy could spoof
those headers to evade limits or poison the ban list. When the service is
exposed behind proxies you do not fully control, override the resolver with
a trust-aware one (for example built on top of [proxy-addr](
https://www.npmjs.com/package/proxy-addr) configured with your known
proxies):

```typescript
import proxyaddr from 'proxy-addr';

const protect = new HttpProtect({
    // trust only your known load balancer subnet
    getClientIp: req => proxyaddr(req, ip => ip === '10.0.0.1'),
});
```

## License

This project is licensed under the GNU General Public License v3.0.
See the [LICENSE](LICENSE)

Happy Coding!
