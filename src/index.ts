/*!
 * Copyright (c) 2018, imqueue.com <support@imqueue.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
import Redis, { RedisOptions } from 'ioredis';
import { getClientIp, Request } from 'request-ip';
import { Networks } from '@imqueue/net';

/**
 * HttpProtectOptions
 * Provides options for HttpProtect class constructor to configure
 * DDoS HTTP protector instance used within express-like web-server.
 */
export interface HttpProtectOptions {
    /**
     * Provides existing ioredis instance to avoid creating new one connection.
     * Use it if you already have ioredis instance in your application.
     */
    redis?: Redis;

    /**
     * Redis connection options. Used only if no redis instance provided.
     * If options are not provided, then default options will be used.
     */
    redisOptions?: RedisOptions;

    /**
     * Redis keys prefix used withing this module.
     * Default is 'imq:http-protect'. Specify your own prefix if you need to
     * use this module with other modules which use the same redis instance.
     *
     * @default 'imq:http-protect'
     */
    redisPrefix?: string;

    /**
     * Time to live for each request counter in seconds. Default is 10 seconds.
     * It means that each request counter will be reset after 10 seconds. Each
     * time new request comes from the same IP address, counter will be
     * TTL extended for another 10 seconds.
     * This option may be configured by passing the value in this options
     * object or by setting HTTP_PROTECT_TTL environment variable with an
     * appropriate integer value.
     *
     * @default 10
     * @see maxRequests
     * @see banLimit
     */
    ttl?: number;

    /**
     * Maximum number of requests allowed per TTL period. Default is 200.
     * So here is a default configuration: 200 requests per 10 seconds. By using
     * ttl & maxRequests options you can configure your own rate limit suitable
     * for your particular HTTP application. Typically, you need to set
     * maxRequests to meaningful number of requests per configured time
     * suitable for a regular user of your application. This option is a basic
     * rule to detect abnormal activity from a user's IP address. When user
     * hits rate limit, the server should respond with 429 Too Many Requests
     * HTTP code error. If it was unintentional requests rate, then user will
     * be able to continue using your application after TTL period. If it was
     * intentional attack, then user will be banned for a longer period of time
     * after hitting ban limit.
     * This option may be configured by passing the value in this options
     * object or by setting HTTP_PROTECT_MAX_REQUESTS environment variable with
     * an appropriate integer value.
     *
     * @default 200
     * @see ttl
     * @see banLimit
     */
    maxRequests?: number;

    /**
     * Ban limit is a maximum number of requests allowed per TTL period after
     * user was banned. Default is 1000. So here is a default configuration:
     * 200 requests per 10 seconds, then 1000 requests per 10 seconds after
     * user was banned. In other words if user makes 20 requests per second
     * you may still treat it as normal behavior. If user hits above 20 requests
     * per second it may be limited with 429 HTTP error and if it  hits 100+
     * requests per second - then it is a suspicious activity deserving banning
     * the traffic source IP address.
     * But operating with longer terms, like 10 seconds instead of 1 second
     * avoids false positives on unintentional requests peaks. Anyway, it is
     * better to set the proper values after understanding the source traffic
     * nature and typical app user activity. In most cases using default values
     * just works fine.
     * This option may be configured by passing the value in this options
     * object or by setting HTTP_PROTECT_BAN_LIMIT environment variable with
     * an appropriate integer value.
     *
     * @default 1000
     * @see maxRequests
     * @see ttl
     */
    banLimit?: number;
}

export interface Response {
    status(code: number): any;
    header?(name: string, value: string): any;
    setHeader?(name: string, value: string): any;
    send(...args: any[]): any;
    end(...args: any[]): any;
}

export { Request } from 'request-ip';

export enum VerificationStatus {
    SAFE,
    LIMITED,
    BANNED,
}

export interface VerificationResponse {
    status: VerificationStatus;
    httpCode: number;
}

export interface NextFunction {
    (...args: any[]): any;
}

const HTTP_TEXT: {
    [code: number]: string;
} = {
    418: 'I\'m a teapot',
    429: 'Too Many Requests',
};

// noinspection JSUnusedGlobalSymbols
/**
 * HttpProtect
 * Provides middleware for express-like web server to protect from DDoS attacks.
 * It uses Redis as a storage for requests counters and block list.
 * It uses @imqueue/net Networks class to deal with block list at runtime.
 */
export default class HttpProtect {
    private redis?: Redis;
    public readonly prefix: string;
    public readonly ttl: number;
    public readonly maxRequests: number;
    public readonly banLimit: number;
    public readonly blockListKey: string;

    public constructor(private options?: HttpProtectOptions) {
        this.redis = options?.redis || this.connect(options?.redisOptions);
        this.prefix = this.options?.redisPrefix || 'imq:http-protect';
        this.maxRequests = this.options?.maxRequests ||
            +(process.env.HTTP_PROTECT_MAX_REQUESTS || 200);
        this.ttl = this.options?.ttl || +(process.env.HTTP_PROTECT_TTL || 10);
        this.banLimit = this.options?.banLimit ||
            +(process.env.HTTP_PROTECT_BAN_LIMIT || 1000);
        this.blockListKey = `${ this.prefix }:block-list`;
    }

    public connect(options?: RedisOptions): Redis {
        this.redis = new Redis(options || {
            host: 'localhost',
            port: 6379,
        });

        return this.redis;
    }

    public async verify(req: Request): Promise<VerificationResponse> {
        if (!this.redis) {
            throw new Error('Redis connection is not established!');
        }

        const ip = getClientIp(req) || '';
        const key = `${ this.prefix }:${ ip }`;

        if (await this.redis?.sismember(this.blockListKey, ip)) {
            return {
                status: VerificationStatus.BANNED,
                httpCode: 418,
            };
        }

        let requests = 1;

        if (!await this.redis?.setnx(key, 1)) {
            requests = await this.redis?.incr(key) || 1;
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

    public async bannedNetworks(): Promise<Networks> {
        // noinspection TypeScriptValidateTypes
        const ips: string[] = await this.redis?.smembers(
            this.blockListKey,
        ) || [];

        return new Networks(ips.map(ip => `${ ip }/32`));
    }

    // noinspection JSUnusedGlobalSymbols
    public async isBanned(ip: string): Promise<boolean> {
        const networks = await this.bannedNetworks();

        return networks.includes(ip);
    }

    public async isLimited(ip: string): Promise<boolean> {
        const key = `${ this.prefix }:${ ip }`;
        const requests = +(await this.redis?.get(key) || 0);

        return requests > this.maxRequests;
    }

    public middleware(): (
        req: Request,
        res: Response,
        next: NextFunction,
    ) => Promise<void> {
        return (req, res, next) => {
            const { status, httpCode } = await this.verify(req);

            if (status === VerificationStatus.SAFE) {
                return next();
            }

            res.status(httpCode);
            res.end();
        };
    }

    public textMiddleware(): (
        req: Request,
        res: Response,
        next: NextFunction,
    ) => Promise<void> {
        return (req, res, next) => {
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

            res.send(`${ httpCode } ${ HTTP_TEXT[httpCode] }`);
            res.end();
        };
    }

    public jsonMiddleware(): (
        req: Request,
        res: Response,
        next: NextFunction,
    ) => Promise<void> {
        return (req, res, next) => {
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

            res.send(JSON.stringify({
                error: {
                    type: 'HTTP',
                    code: httpCode,
                    message: HTTP_TEXT[httpCode],
                },
            }));
            res.end();
        };
    }

    destroy(): void {
        this.redis?.disconnect();
        this.redis = undefined;
    }
}
