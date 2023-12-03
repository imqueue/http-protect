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
import { getClientIp } from 'request-ip';

// inside some async function in the code
const protect = new HttpProtect();
const { status, httpCode } = await protect.verify(getClientIp(req));

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

```typescript
import HttpProtect from '@imqueue/http-protect';

const protect = new HttpProtect();

// get the list of banned networks
console.log(protect.bannedNetworks().toJSON());

// check if given IP is currently banned or not
console.log(protect.isBanned('127.0.0.1'));

// check if given IP is currently limited or not
console.log(protect.isLimited('127.0.0.1'));
```

This module uses redis server to deal with requests counters and banned 
networks. It also based on ioredis module to connect to redis server, so
you might want to configure it via constructor options or bypass existing
ioredis instance in the options. Please, refer `HttpProtectOptions` interface
for more details.

## License

[ISC](https://github.com/imqueue/http-protect/blob/master/LICENSE)

Happy Coding!
