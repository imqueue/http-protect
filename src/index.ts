/*!
 * I'm Queue Software Project
 * Copyright (C) 2025  imqueue.com <support@imqueue.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * If you want to use this code in a closed source (commercial) project, you can
 * purchase a proprietary commercial license. Please contact us at
 * <support@imqueue.com> to get commercial licensing options.
 */
/**
 * Rate limiting and IP banning for express-like HTTP servers, backed by Redis.
 *
 * {@link HttpProtect} counts requests per client IP and, past two configurable
 * thresholds, first answers 429 and then adds the address to a persistent block
 * list answered with 418. Mount it as {@link HttpProtect.jsonMiddleware},
 * {@link HttpProtect.textMiddleware} or {@link HttpProtect.middleware}, or call
 * {@link HttpProtect.verify} yourself and act on the
 * {@link VerificationStatus} it returns.
 *
 * @remarks
 * Three things about this package are load-bearing and none of them is visible in
 * a signature.
 *
 * A ban is permanent. Addresses go into a Redis set that is never given an
 * expiry and never written to again, and there is no method here that removes one
 * — so an address stays banned until something outside this package deletes it
 * from Redis. Read {@link HttpProtect.banLimit} before choosing a value for it.
 *
 * The request counter measures a continuous stream, not a fixed window. Its TTL
 * is pushed back to {@link HttpProtect.ttl} on every request, so the count only
 * resets after a full `ttl` of silence from that address. A client that keeps
 * making requests accumulates indefinitely, which is why the default
 * {@link HttpProtect.maxRequests} of 200 stops a steady 1-per-second client after
 * about 200 seconds and not just a 200-request burst.
 *
 * Everything is keyed by the client IP, and by default that comes from proxy
 * headers a client can set. See {@link HttpProtectOptions.getClientIp} before
 * exposing this to the internet behind a proxy you do not control.
 *
 * @example
 * ```typescript
 * import HttpProtect from '@imqueue/http-protect';
 *
 * // 429 then 418, as JSON, using default thresholds and a local Redis
 * app.use(new HttpProtect().jsonMiddleware());
 * ```
 *
 * @example
 * ```typescript
 * import HttpProtect, { VerificationStatus } from '@imqueue/http-protect';
 *
 * const protect = new HttpProtect({ ttl: 60, maxRequests: 600, banLimit: 5000 });
 * const { status, httpCode } = await protect.verify(req);
 *
 * if (status !== VerificationStatus.SAFE) {
 *     res.status(httpCode).end();
 * }
 * ```
 *
 * @packageDocumentation
 */

import { Redis, type RedisOptions } from 'ioredis';
import { getClientIp, type Request } from 'request-ip';
import { isValid, Networks } from '@imqueue/net';

/**
 * Configuration for the {@link HttpProtect} constructor.
 *
 * @remarks
 * Every option has a working default, so `new HttpProtect()` is valid — but it
 * connects to `localhost:6379` and rate-limits on proxy-supplied headers, which
 * is rarely what a deployed service wants.
 *
 * {@link HttpProtectOptions.ttl}, {@link HttpProtectOptions.maxRequests} and
 * {@link HttpProtectOptions.banLimit} can each also come from an environment
 * variable, and an option passed here wins over its variable.
 */
export interface HttpProtectOptions {
    /**
     * An existing ioredis client to use instead of opening another connection.
     *
     * @remarks
     * Pass this if your application already has a client. Supplying it also
     * prevents the constructor from connecting on its own, which is the only way
     * to construct a {@link HttpProtect} without immediately opening a socket.
     * Note that {@link HttpProtect.destroy} disconnects whichever client it is
     * holding, including one passed in here.
     */
    redis?: Redis;

    /**
     * ioredis connection options, used only when {@link HttpProtectOptions.redis}
     * is not given.
     *
     * @remarks
     * Omitting both means the constructor connects to `localhost:6379`. There is
     * no lazy mode: the connection is opened by the constructor, so a
     * {@link HttpProtect} built in a process with no Redis reachable will emit
     * ioredis connection errors on its own client rather than failing to
     * construct.
     */
    redisOptions?: RedisOptions;

    /**
     * Prefix for every Redis key this module writes.
     *
     * @remarks
     * Two things live under it: one counter key per client IP, and the single
     * block-list set at `<prefix>:block-list`. Change it when another module
     * shares the same Redis instance, and keep it stable across deployments —
     * changing it abandons the existing counters and, more importantly, the
     * existing bans, since nothing migrates them.
     *
     * @defaultValue `'imq:http-protect'`
     */
    redisPrefix?: string;

    /**
     * Seconds of silence from an address before its request counter is forgotten.
     *
     * @remarks
     * Read it as an idle timeout rather than a window length. The counter's TTL is
     * pushed back to this value on every request from that address, so the count
     * survives for as long as the address keeps making requests and is discarded
     * only after a full `ttl` with none. A client that never pauses that long is
     * counted cumulatively until it reaches {@link HttpProtectOptions.maxRequests}
     * and then {@link HttpProtectOptions.banLimit}, no matter how slowly it goes.
     *
     * Also settable as `HTTP_PROTECT_TTL`; a value passed here wins. Both are read
     * once, in the constructor.
     *
     * @defaultValue `10`
     */
    ttl?: number;

    /**
     * Requests an address may accumulate before it is answered 429.
     *
     * @remarks
     * Exceeding it yields {@link VerificationStatus.LIMITED} and HTTP 429, and the
     * address recovers by going quiet for {@link HttpProtectOptions.ttl} seconds —
     * this threshold carries no lasting consequence on its own.
     *
     * Choose the value against a continuous stream rather than a rate, because
     * that is what the counter measures (see {@link HttpProtectOptions.ttl}). At
     * the defaults, 200 requests inside 10 seconds trips it, and so does one
     * request per second for 200 seconds — the second of which is ordinary
     * behaviour for a real user on a busy page. Raise it, or raise `ttl` and this
     * together, if legitimate sessions are long-lived.
     *
     * Also settable as `HTTP_PROTECT_MAX_REQUESTS`; a value passed here wins.
     *
     * @defaultValue `200`
     */
    maxRequests?: number;

    /**
     * Requests an address may accumulate before it is banned outright.
     *
     * @remarks
     * Crossing it adds the address to the block list, and from then on every
     * request from it is answered {@link VerificationStatus.BANNED} with HTTP 418
     * without any counting.
     *
     * Set this deliberately, because the ban does not lapse. The address is added
     * to a Redis set that carries no expiry, nothing in this package removes an
     * entry from it, and the block-list check runs before the counter — so going
     * quiet does not help, and there is no supported way to reverse it from this
     * API. Lifting a ban means deleting the address from `<prefix>:block-list` in
     * Redis yourself. Treat the default as "block this source until a human looks
     * at it", and prefer a high value to a low one: at the defaults, a client
     * held at one request per second reaches 1000 in under 17 minutes of ordinary
     * use.
     *
     * Also settable as `HTTP_PROTECT_BAN_LIMIT`; a value passed here wins.
     *
     * @defaultValue `1000`
     */
    banLimit?: number;

    /**
     * CIDR networks exempt from counting, limiting and banning.
     *
     * @remarks
     * Matching addresses short-circuit {@link HttpProtect.verify} before it
     * touches Redis, so they are never counted and can never be banned — which
     * also means an exempt address is answered `SAFE` even when Redis is
     * unreachable. Use it for your own services, health checks and monitoring.
     *
     * Every entry must carry a prefix length. `10.0.0.0/8` is a network and
     * `203.0.113.7/32` is a single host, but a bare `203.0.113.7` is rejected —
     * `@imqueue/net` throws while parsing it, so the {@link HttpProtect}
     * constructor throws too. Use `/32` for one IPv4 host and `/128` for one IPv6
     * host. The list is read once, in the constructor, into
     * {@link HttpProtect.safeNetworks}; adding to it later needs a new instance.
     *
     * @defaultValue `[]` — nothing is exempt
     */
    safeNetworks?: string[];

    /**
     * Resolver used to extract the client IP address from an incoming
     * request. By default request-ip's getClientIp() is used, which reads
     * the usual proxy headers (x-forwarded-for, x-real-ip, etc.).
     *
     * Because bans and rate limits are keyed by this address, blindly
     * trusting forwarded headers lets a client spoof its IP. Override this
     * with a trust-aware resolver (for example one built on top of the
     * `proxy-addr` package, configured with your known proxies) when the
     * service is exposed behind proxies you do not fully control.
     *
     * Spoofing cuts both ways here, and the second direction is the worse one.
     * A client that varies the header evades its own counter; a client that
     * forges someone else's address spends that address's budget and can get it
     * banned — permanently, per {@link HttpProtectOptions.banLimit}. So on an
     * untrusted path this option is the difference between a rate limiter and a
     * way to have arbitrary third parties blocked.
     *
     * @param req - the incoming request, as passed to
     * {@link HttpProtect.verify} or to one of the middlewares
     * @returns The client's IP address, or `null` when it cannot be determined.
     * A `null` — or anything that is not a valid address — makes
     * {@link HttpProtect.verify} answer `LIMITED` for that request, since a client
     * it cannot name is a client it cannot rate-limit.
     */
    getClientIp?: (req: Request) => string | null;
}

/**
 * The minimum a response object must provide for the middlewares to answer with.
 *
 * @remarks
 * Structural on purpose, so express, Fastify's compatibility layer, a bare
 * `http.ServerResponse` wrapper or a test double all satisfy it without this
 * package depending on any of them.
 *
 * `Response.header()` and `Response.setHeader()` are both optional
 * because frameworks disagree on which they provide;
 * {@link HttpProtect.textMiddleware} and {@link HttpProtect.jsonMiddleware} prefer
 * `header`, fall back to `setHeader`, and simply send no `Content-Type` if neither
 * is a function.
 */
export interface Response {
    /**
     * Sets the HTTP status code. Called with 429 or 418 before the body is sent.
     *
     * @param code - the status code to respond with
     * @returns Ignored — the middlewares never read it, so returning `this` for
     * chaining is fine.
     */
    status(code: number): any;

    /**
     * Express-style header setter, preferred when present.
     *
     * @param name - the header name
     * @param value - the header value
     * @returns Ignored by the middlewares.
     */
    header?(name: string, value: string): any;

    /**
     * Node-style header setter, used only when `Response.header()` is absent.
     *
     * @param name - the header name
     * @param value - the header value
     * @returns Ignored by the middlewares.
     */
    setHeader?(name: string, value: string): any;

    /**
     * Writes the response body. Given a plain string by
     * {@link HttpProtect.textMiddleware} and a JSON string by
     * {@link HttpProtect.jsonMiddleware}; never called by
     * {@link HttpProtect.middleware}, which answers with no body at all.
     *
     * @param args - passed straight through from the middleware
     * @returns Ignored by the middlewares.
     */
    send(...args: any[]): any;

    /**
     * Ends the response. Called by every middleware on a rejected request,
     * including after `Response.send()`.
     *
     * @param args - passed straight through from the middleware
     * @returns Ignored by the middlewares.
     */
    end(...args: any[]): any;
}

/**
 * The incoming request shape, re-exported from `request-ip`.
 *
 * @remarks
 * Only the fields a resolver reads — proxy headers and the various
 * `remoteAddress` locations — so a real express request satisfies it. It is
 * re-exported so that a custom {@link HttpProtectOptions.getClientIp} can be
 * typed without depending on `request-ip` directly.
 */
export type { Request } from 'request-ip';

/**
 * What {@link HttpProtect.verify} concluded about a request.
 *
 * @remarks
 * Only `SAFE` means "serve it". The two rejection values differ in how the client
 * recovers, not in how you should respond: `LIMITED` lapses on its own, `BANNED`
 * does not.
 */
export enum VerificationStatus {
    /**
     * Serve the request. Either the address is within
     * {@link HttpProtectOptions.safeNetworks}, or its count is still under
     * {@link HttpProtectOptions.maxRequests}. Paired with HTTP 200.
     */
    SAFE,

    /**
     * Rate limited: the address is over {@link HttpProtectOptions.maxRequests} but
     * under {@link HttpProtectOptions.banLimit}. Paired with HTTP 429. Recovers by
     * itself once the address is quiet for {@link HttpProtectOptions.ttl} seconds.
     *
     * @remarks
     * Also returned for a request whose client IP could not be resolved, which is
     * refused without being counted — see {@link HttpProtect.verify}. So this value
     * means "not served, and not permanently", not specifically "over the limit".
     */
    LIMITED,

    /**
     * On the block list, having passed {@link HttpProtectOptions.banLimit}. Paired
     * with HTTP 418. Does not recover — see {@link HttpProtectOptions.banLimit}.
     */
    BANNED,
}

/**
 * The verdict {@link HttpProtect.verify} returns.
 */
export interface VerificationResponse {
    /** What was decided about the request. */
    status: VerificationStatus;

    /**
     * The status code matching {@link VerificationResponse.status} — 200 for
     * `SAFE`, 429 for `LIMITED`, 418 for `BANNED`.
     *
     * @remarks
     * 418 rather than another 429 is deliberate, so that a ban is
     * distinguishable from a rate limit in logs and at the edge. It is not a
     * status code clients or CDNs treat meaningfully, so translate it if that
     * matters to you.
     */
    httpCode: number;
}

/**
 * The `next()` callback an express-like framework passes to a middleware.
 *
 * @remarks
 * The middlewares here call it with no arguments, and only for a request that
 * passed. A rejected request is answered directly and `next` is never called, so
 * nothing downstream runs.
 */
export interface NextFunction {
    /**
     * Hands control to the next middleware.
     *
     * @param args - accepted for signature compatibility; never supplied here
     * @returns Ignored.
     */
    (...args: any[]): any;
}

const HTTP_TEXT: {
    [code: number]: string;
} = {
    418: "I'm a teapot",
    429: 'Too Many Requests',
};

/**
 * Per-IP request counting, rate limiting and banning for an express-like server.
 *
 * @remarks
 * Counters and the block list live in Redis, so several processes behind a load
 * balancer share one view of a client. `Networks` from `@imqueue/net` does the
 * CIDR matching for {@link HttpProtect.safeNetworks}.
 *
 * Constructing one opens a Redis connection unless
 * {@link HttpProtectOptions.redis} supplies a client, and reads every threshold
 * once — from the options, then from the environment. Changing an environment
 * variable afterwards has no effect on a live instance.
 *
 * The thresholds are not a rate. See {@link HttpProtect.ttl} for what the counter
 * actually measures, and {@link HttpProtectOptions.banLimit} for how long a ban
 * lasts, before putting this in front of real traffic.
 */
export default class HttpProtect {
    private redis?: Redis;

    /**
     * The resolved Redis key prefix, from
     * {@link HttpProtectOptions.redisPrefix}.
     */
    public readonly prefix: string;

    /**
     * The resolved idle timeout in seconds, from {@link HttpProtectOptions.ttl},
     * `HTTP_PROTECT_TTL`, or 10.
     *
     * @remarks
     * Applied to a counter key on every request from that address, so it bounds
     * the gap between requests rather than the age of the count. An address that
     * never pauses this long keeps one counter for as long as it keeps asking.
     */
    public readonly ttl: number;

    /**
     * The resolved 429 threshold, from {@link HttpProtectOptions.maxRequests},
     * `HTTP_PROTECT_MAX_REQUESTS`, or 200.
     */
    public readonly maxRequests: number;

    /**
     * The resolved ban threshold, from {@link HttpProtectOptions.banLimit},
     * `HTTP_PROTECT_BAN_LIMIT`, or 1000.
     */
    public readonly banLimit: number;

    /**
     * The Redis key of the block-list set, `<prefix>:block-list`.
     *
     * @remarks
     * Exposed because it is the only way to lift a ban: nothing in this class
     * removes a member, so an operator or another service has to `SREM` the
     * address from this set. The set has no expiry.
     */
    public readonly blockListKey: string;

    /**
     * The parsed exempt networks, from {@link HttpProtectOptions.safeNetworks}.
     *
     * @remarks
     * Read-only and fixed at construction. Empty unless the option was given, in
     * which case nothing is exempt.
     */
    public readonly safeNetworks: Networks;

    /**
     * Resolves the client IP for a request — `request-ip`'s `getClientIp` unless
     * {@link HttpProtectOptions.getClientIp} replaced it.
     *
     * @remarks
     * Everything this class stores is keyed by what this returns, so it is the
     * single point that decides whose budget a request spends.
     */
    public readonly getClientIp: (req: Request) => string | null;

    /**
     * Resolves every threshold, parses the exempt networks and connects to Redis.
     *
     * @param options - configuration; every field is optional, and omitting the
     * object entirely gives default thresholds against `localhost:6379`
     *
     * @remarks
     * Connects immediately unless {@link HttpProtectOptions.redis} is supplied,
     * so this is not a cheap object to build in a process that has no Redis.
     *
     * @throws TypeError if any {@link HttpProtectOptions.safeNetworks} entry is
     * not valid CIDR — including a bare address with no prefix length.
     *
     * @example
     * ```typescript
     * const protect = new HttpProtect({
     *     redis: existingClient,
     *     ttl: 60,
     *     maxRequests: 600,
     *     banLimit: 10000,
     *     safeNetworks: ['10.0.0.0/8', '203.0.113.7/32'],
     * });
     * ```
     */
    public constructor(private options?: HttpProtectOptions) {
        this.redis = options?.redis || this.connect(options?.redisOptions);
        this.prefix = this.options?.redisPrefix || 'imq:http-protect';
        this.maxRequests =
            this.options?.maxRequests ||
            +(process.env.HTTP_PROTECT_MAX_REQUESTS || 200);
        this.ttl = this.options?.ttl || +(process.env.HTTP_PROTECT_TTL || 10);
        this.banLimit =
            this.options?.banLimit ||
            +(process.env.HTTP_PROTECT_BAN_LIMIT || 1000);
        this.blockListKey = `${this.prefix}:block-list`;
        this.safeNetworks = new Networks(this.options?.safeNetworks || []);
        this.getClientIp = this.options?.getClientIp || getClientIp;
    }

    /**
     * Opens a Redis connection and adopts it as this instance's client.
     *
     * @param options - ioredis options; omitted means `localhost:6379`
     * @returns The newly created client, which is also stored on this instance.
     *
     * @remarks
     * Called by the constructor when no client was supplied. Calling it again
     * replaces the current client without disconnecting the old one, so a repeat
     * call leaks a connection — use it to reconnect after
     * {@link HttpProtect.destroy}, not to reconfigure a live instance.
     */
    public connect(options?: RedisOptions): Redis {
        this.redis = new Redis(
            options || {
                host: 'localhost',
                port: 6379,
            },
        );

        return this.redis;
    }

    /**
     * Counts a request against its client IP and decides whether to serve it.
     *
     * @param req - the incoming request, from which the client IP is resolved
     * with {@link HttpProtect.getClientIp}
     * @returns The verdict and its matching HTTP status code.
     *
     * @remarks
     * This is the whole decision, and it has side effects: it increments the
     * address's counter, refreshes that counter's TTL to {@link HttpProtect.ttl},
     * and adds the address to {@link HttpProtect.blockListKey} once it passes
     * {@link HttpProtect.banLimit}. Calling it twice counts twice, so the
     * middlewares call it exactly once per request and you should too.
     *
     * The order matters. A request whose client cannot be named at all — the
     * resolver returned `null`, or a custom one returned something that is not an
     * address — is answered `LIMITED` immediately, before Redis is touched: it
     * cannot be counted, so it is refused rather than served, and it is kept out
     * of the shared state entirely. An address in {@link HttpProtect.safeNetworks}
     * then returns `SAFE`, also without touching Redis, so exempt traffic is
     * served even when Redis is down. A banned address returns `BANNED` before the
     * counter is read, so a ban costs one `SISMEMBER` and nothing accumulates
     * behind it.
     *
     * @throws Error `'Redis connection is not established!'` when there is no
     * client — that is, after {@link HttpProtect.destroy} — and the address is
     * neither unidentifiable nor exempt.
     */
    public async verify(req: Request): Promise<VerificationResponse> {
        const ip = this.getClientIp(req) || '';

        if (!isValid(ip)) {
            // The resolver could not name the client — it returned null, or a
            // custom one returned something that is not an address. Such a
            // request cannot be counted, so refuse it rather than serve it
            // unchecked. Deliberately without touching Redis: pooling every
            // unidentifiable client under one key would let a single one of them
            // exhaust that counter and, past banLimit, ban the whole pool with a
            // ban nothing here can lift.
            return {
                status: VerificationStatus.LIMITED,
                httpCode: 429,
            };
        }

        if (this.isSafeIp(ip)) {
            return {
                status: VerificationStatus.SAFE,
                httpCode: 200,
            };
        }

        if (!this.redis) {
            throw new Error('Redis connection is not established!');
        }

        const key = `${this.prefix}:${ip}`;

        if (await this.redis?.sismember(this.blockListKey, ip)) {
            return {
                status: VerificationStatus.BANNED,
                httpCode: 418,
            };
        }

        let requests = 1;

        if (!(await this.redis?.setnx(key, 1))) {
            requests = (await this.redis?.incr(key)) || 1;
        }

        // noinspection TypeScriptValidateTypes
        await this.redis?.expire(key, this.ttl);

        if (requests > this.maxRequests) {
            if (requests > this.banLimit) {
                // noinspection TypeScriptValidateTypes
                await this.redis?.sadd(this.blockListKey, ip);

                return {
                    status: VerificationStatus.BANNED,
                    httpCode: 418,
                };
            }

            return {
                status: VerificationStatus.LIMITED,
                httpCode: 429,
            };
        }

        return {
            status: VerificationStatus.SAFE,
            httpCode: 200,
        };
    }

    /**
     * The current block list, as a `Networks` object.
     *
     * @returns Every banned address, each widened to a `/32` network.
     *
     * @remarks
     * Reads the whole set on every call and builds a fresh `Networks`, so it costs
     * an `SMEMBERS` plus parsing — fine for an admin endpoint, not for a hot path.
     *
     * The `/32` suffix is applied to every address regardless of family, which is
     * correct for IPv4 and wrong for IPv6: a `/32` IPv6 prefix covers 2^96
     * addresses, so a single banned IPv6 address makes this object match a vast
     * range around it. {@link HttpProtect.verify} does not use this — it matches
     * exact addresses in Redis — so real blocking is unaffected, but
     * {@link HttpProtect.isBanned} inherits the over-match. Do not use either as
     * an authority for IPv6.
     */
    public async bannedNetworks(): Promise<Networks> {
        // noinspection TypeScriptValidateTypes
        const ips: string[] =
            (await this.redis?.smembers(this.blockListKey)) || [];

        return new Networks(ips.map(ip => `${ip}/32`));
    }

    /**
     * Whether an address is currently on the block list.
     *
     * @param ip - the address to check, without a prefix length
     * @returns `true` if it is banned.
     *
     * @remarks
     * Asynchronous, and it reloads the entire block list to answer — via
     * {@link HttpProtect.bannedNetworks}, whose IPv6 over-match it inherits, so
     * this can return `true` for an IPv6 address that was never banned. For IPv4
     * it is exact.
     *
     * @throws TypeError if `ip` is not a valid address, including an empty string.
     */
    public async isBanned(ip: string): Promise<boolean> {
        const networks = await this.bannedNetworks();

        return networks.includes(ip);
    }

    /**
     * Whether an address is currently over the 429 threshold.
     *
     * @param ip - the address to check
     * @returns `true` if its live counter exceeds {@link HttpProtect.maxRequests}.
     *
     * @remarks
     * Read-only: it neither counts the call nor refreshes the counter's TTL. A
     * missing key reads as zero, so an address that has been quiet for
     * {@link HttpProtect.ttl} reports `false`.
     *
     * It does not consult the block list, so a banned address reports `false` here
     * once its counter lapses. Check {@link HttpProtect.isBanned} as well to get
     * the whole picture.
     */
    public async isLimited(ip: string): Promise<boolean> {
        const key = `${this.prefix}:${ip}`;
        const requests = +((await this.redis?.get(key)) || 0);

        return requests > this.maxRequests;
    }

    /**
     * A middleware that rejects with a bare status code and no body.
     *
     * @returns An async middleware to hand to `app.use()`.
     *
     * @remarks
     * The leanest of the three: a rejected request gets its status and
     * `Response.end()`, with no `Content-Type` and nothing written. Prefer
     * {@link HttpProtect.jsonMiddleware} for an API whose clients parse errors, or
     * {@link HttpProtect.textMiddleware} for something a human might read.
     *
     * Mount it first, before body parsing and routing, so a rejected request costs
     * as little as possible.
     *
     * @example
     * ```typescript
     * app.use(new HttpProtect().middleware());
     * ```
     */
    public middleware(): (
        req: Request,
        res: Response,
        next: NextFunction,
    ) => Promise<void> {
        return async (req, res, next) => {
            const { status, httpCode } = await this.verify(req);

            if (status === VerificationStatus.SAFE) {
                return next();
            }

            res.status(httpCode);
            res.end();
        };
    }

    /**
     * A middleware that rejects with `text/plain`.
     *
     * @returns An async middleware to hand to `app.use()`.
     *
     * @remarks
     * Sends the code and its reason phrase — `429 Too Many Requests`, or
     * `418 I'm a teapot` for a ban. Sets `Content-Type` through
     * `Response.header()` if the framework has it, `Response.setHeader()`
     * otherwise, and omits it if neither exists.
     */
    public textMiddleware(): (
        req: Request,
        res: Response,
        next: NextFunction,
    ) => Promise<void> {
        return async (req, res, next) => {
            const { status, httpCode } = await this.verify(req);

            if (status === VerificationStatus.SAFE) {
                return next();
            }

            res.status(httpCode);

            if (typeof res.header === 'function') {
                res.header('Content-Type', 'text/plain');
            } else if (typeof res.setHeader === 'function') {
                res.setHeader('Content-Type', 'text/plain');
            }

            res.send(`${httpCode} ${HTTP_TEXT[httpCode]}`);
            res.end();
        };
    }

    /**
     * A middleware that rejects with a JSON error body.
     *
     * @returns An async middleware to hand to `app.use()`.
     *
     * @remarks
     * The usual choice for an API. The body is
     * `{"error":{"type":"HTTP","code":429,"message":"Too Many Requests"}}`, with
     * 418 and `I'm a teapot` for a ban. `Content-Type` is set as described in
     * {@link HttpProtect.textMiddleware}.
     *
     * @example
     * ```typescript
     * const protect = new HttpProtect({ redis: existingClient });
     *
     * app.use(protect.jsonMiddleware());
     * ```
     */
    public jsonMiddleware(): (
        req: Request,
        res: Response,
        next: NextFunction,
    ) => Promise<void> {
        return async (req, res, next) => {
            const { status, httpCode } = await this.verify(req);

            if (status === VerificationStatus.SAFE) {
                return next();
            }

            res.status(httpCode);

            if (typeof res.header === 'function') {
                res.header('Content-Type', 'application/json');
            } else if (typeof res.setHeader === 'function') {
                res.setHeader('Content-Type', 'application/json');
            }

            res.send(
                JSON.stringify({
                    error: {
                        type: 'HTTP',
                        code: httpCode,
                        message: HTTP_TEXT[httpCode],
                    },
                }),
            );
            res.end();
        };
    }

    /**
     * Disconnects the Redis client and drops it.
     *
     * @remarks
     * Disconnects whichever client this instance holds — including one passed in
     * as {@link HttpProtectOptions.redis}, which the rest of your application may
     * still be using. Share a client only if you also control who shuts it down.
     *
     * Counters and bans are unaffected: they live in Redis and outlive the
     * instance. Afterwards {@link HttpProtect.verify} throws for any non-exempt
     * address until {@link HttpProtect.connect} is called again.
     */
    destroy(): void {
        this.redis?.disconnect();
        this.redis = undefined;
    }

    private isSafeIp(ip: string): boolean {
        return this.safeNetworks.includes(ip);
    }
}
