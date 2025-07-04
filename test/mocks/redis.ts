/*!
 * IMQ Unit Test Mocks: redis
 *
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
import * as mock from 'mock-require';
import { EventEmitter } from 'events';
import * as crypto from 'crypto';

function sha1(str: string) {
    const sha: crypto.Hash = crypto.createHash('sha1');
    sha.update(str);
    return sha.digest('hex');
}

/**
 * @implements {IRedisClient}
 */
export class RedisClientMock extends EventEmitter {
    private static __queues__: any = {};
    private static __clientList: any = {};
    private __rt: any;
    private static __keys: any = {};
    private static __sets: any = {};
    private static __scripts: any = {};
    private static __expirations: any = {};
    private __name: string = '';
    // noinspection JSUnusedGlobalSymbols
    public connected: boolean = true;
    public status = 'ready';

    constructor(options: any = {}) {
        super();
        setTimeout(() => {
            this.emit('ready', this);
        });

        if (options.connectionName) {
            this.__name = options.connectionName;
            RedisClientMock.__clientList[options.connectionName] = true;
        }
    }

    // noinspection JSUnusedGlobalSymbols
    public end() {}
    // noinspection JSUnusedGlobalSymbols
    public quit() {}

    // noinspection JSMethodCanBeStatic
    public set(...args: any[]): number {
        const [key, val] = args;
        RedisClientMock.__keys[key] = val;
        this.cbExecute(args.pop(), null, 1);
        return 1;
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public setnx(...args: any[]): number {
        const self = RedisClientMock;
        const key = args.shift();
        let result = 0;
        if (/:watch:lock$/.test(key)) {  // This condition is too restrictive!
            if (typeof self.__keys[key] === 'undefined') {
                self.__keys[key] = args.shift();
                result = 1;
            }
        }

        this.cbExecute(args.pop(), null, result);
        return result;
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public get(...args: any[]): string | null {
        const self = RedisClientMock;
        const key = args.shift();
        const cb = args.length > 0 ? args.pop() : undefined;

        const result = self.__keys[key] !== undefined
            ? String(self.__keys[key])
            : null
        ;

        if (cb) {
            setTimeout(() => this.cbExecute(cb, null, result), 0);
        }

        return result;
    }

    // noinspection JSMethodCanBeStatic
    public exists(...args: any[]): number {
        const self = RedisClientMock;
        const key = args.shift();
        const cb = args.pop();

        const result = (self.__keys[key] !== undefined ||
            self.__sets[key] !== undefined ||
            self.__queues__[key] !== undefined) ? 1 : 0;

        this.cbExecute(cb, null, result);
        return result;
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public sadd(...args: any[]): number {
        const self = RedisClientMock;
        const key = args.shift();
        let addedCount = 0;

        if (!self.__sets[key]) {
            self.__sets[key] = new Set();
        }

        // Extract callback if present (it's the last argument)
        const cb = typeof args[args.length - 1] === 'function'
            ? args.pop()
            : undefined;

        // Add all remaining values to the set
        for (const value of args) {
            const sizeBefore = self.__sets[key].size;
            self.__sets[key].add(value);
            if (self.__sets[key].size > sizeBefore) {
                addedCount++;
            }
        }

        this.cbExecute(cb, null, addedCount);
        return addedCount;
    }


    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public sismember(...args: any[]): number {
        const self = RedisClientMock;
        const key = args.shift();
        const member = args.shift();
        const cb = args.pop();

        const result = self.__sets[key] && self.__sets[key].has(member) ? 1 : 0;
        this.cbExecute(cb, null, result);
        return result;
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public expire(...args: any[]): number {
        const self = RedisClientMock;
        const key = args.shift();
        const seconds = args.shift();
        const cb = args.pop();

        let result = 0;

        // Check if key exists in any storage
        if (self.__keys[key] !== undefined ||
            self.__sets[key] !== undefined ||
            self.__queues__[key] !== undefined) {

            // Set expiration
            self.__expirations[key] = Date.now() + (seconds * 1000);

            // Set timeout to delete the key
            setTimeout(() => {
                delete self.__keys[key];
                delete self.__sets[key];
                delete self.__queues__[key];
                delete self.__expirations[key];
            }, seconds * 1000);

            result = 1;
        }

        this.cbExecute(cb, null, result);
        return result;
    }

    // noinspection TypescriptExplicitMemberType,JSMethodCanBeStatic
    public lpush(key: string, value: any, cb?: any): number {
        const self = RedisClientMock;
        if (!self.__queues__[key]) {
            self.__queues__[key] = [];
        }
        self.__queues__[key].push(value);
        this.cbExecute(cb, null, 1);
        return 1;
    }

    public async brpop(...args: any[]): Promise<string[]> {
        const [key, timeout, cb] = args;
        const q = RedisClientMock.__queues__[key] || [];
        if (!q.length) {
            this.__rt && clearTimeout(this.__rt);

            return new Promise(resolve => {
                this.__rt = setTimeout(() => resolve(this.brpop(
                    key, timeout, cb,
                )), timeout || 100);
            });
        } else {
            const result = [key, q.shift()];

            this.cbExecute(cb, null, [key, q.shift()]);

            return result;
        }
    }

    public async brpoplpush(
        from: string,
        to: string,
        timeout: number,
        cb?: Function
    ): Promise<string> {
        const fromQ = RedisClientMock.__queues__[from] =
            RedisClientMock.__queues__[from] || [];
        const toQ = RedisClientMock.__queues__[to] =
            RedisClientMock.__queues__[to] || [];
        if (!fromQ.length) {
            this.__rt && clearTimeout(this.__rt);

            return new Promise(resolve => {
                this.__rt = setTimeout(() => resolve(this.brpoplpush(
                    from, to, timeout, cb,
                )), timeout || 100);
            });
        } else {
            toQ.push(fromQ.shift());
            cb && cb(null, '1');

            return '1';
        }
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public lrange(
        key: string,
        start: number,
        stop: number,
        cb?: Function,
    ): boolean {
        const q = RedisClientMock.__queues__[key] =
            RedisClientMock.__queues__[key] || [];
        const result = q.splice(start, stop);
        this.cbExecute(cb, null, result);
        return result;
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public scan(...args: any[]): (string | string[])[] {
        const cb = args.pop();
        const qs = RedisClientMock.__queues__;
        const found: string[] = [];
        for (let q of Object.keys(qs)) {
            if (q.match(/worker/)) {
                found.push(q);
            }
        }
        const result = ['0', found];
        this.cbExecute(cb, null, result);
        return result;
    }

    // noinspection JSMethodCanBeStatic
    public script(...args: any[]): unknown {
        const cmd = args.shift();
        const scriptOrHash = args.shift();
        const cb = args.pop();
        const isCb = typeof cb === 'function';

        if (cmd === 'LOAD') {
            const hash = sha1(scriptOrHash);
            RedisClientMock.__scripts[hash] = scriptOrHash;
            isCb && cb(null, hash);
            return hash;
        }
        if (cmd === 'EXISTS') {
            const hash = RedisClientMock.__scripts[scriptOrHash] !== undefined;

            isCb && cb(null, hash);

            return [Number(hash)];
        }

        return [0];
    }

    // noinspection JSUnusedGlobalSymbols
    public client(...args: any[]): string | boolean {
        const self = RedisClientMock;
        const cmd = args.shift();
        const cb = args.pop();
        const name = args.shift();

        if (cmd === 'LIST') {
            const result = Object.keys(self.__clientList)
            .map((name: string, id: number) => `id=${id} name=${name}`)
            .join('\n');

            this.cbExecute(cb, null, result);
            return result;
        }
        else if (cmd === 'SETNAME') {
            this.__name = name;
            self.__clientList[name] = true;
        }

        this.cbExecute(cb, null, true);
        return true;
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public psubscribe(...args: any[]): number {
        this.cbExecute(args.pop(), null, 1);
        return 1;
    }

    public punsubscribe(...args: any[]): number {
        this.cbExecute(args.pop(), null, 1);
        return 1;
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public evalsha(...args: any[]): boolean {
        this.cbExecute(args.pop());
        return true;
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public del(...args: any[]): number {
        const self = RedisClientMock;
        let count = 0;
        for (let key of args) {
            if (self.__keys[key] !== undefined) {
                delete self.__keys[key];
                count++;
            }
            if (self.__queues__[key] !== undefined) {
                delete self.__queues__[key];
                count++;
            }
            if (self.__sets[key] !== undefined) {
                delete self.__sets[key];
                count++;
            }
            if (self.__expirations[key] !== undefined) {
                delete self.__expirations[key];
            }
        }
        this.cbExecute(args.pop(), count);
        return count;
    }

    // noinspection JSUnusedGlobalSymbols
    public zadd(...args: any[]): boolean {
        const [key, score, value, cb] = args;
        const timeout = score - Date.now();
        setTimeout(() => {
            const toKey = key.split(/:/).slice(0,2).join(':');
            this.lpush(toKey, value);
        }, timeout);
        this.cbExecute(cb);
        return true;
    }

    public incr(...args: any[]): number {
        const self = RedisClientMock;
        const key = args.shift();
        const cb = args.pop();

        // Initialize key to 0 if it doesn't exist
        if (self.__keys[key] === undefined) {
            self.__keys[key] = 0;
        }

        // Convert to number and increment
        const currentValue = parseInt(self.__keys[key]) || 0;
        const newValue = currentValue + 1;
        self.__keys[key] = newValue;

        this.cbExecute(cb, null, newValue);
        return newValue;
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public smembers(...args: any[]): string[] {
        const self = RedisClientMock;
        const key = args.shift();
        const cb = typeof args[args.length - 1] === 'function' ? args.pop() : undefined;

        const result = self.__sets[key] ? Array.from(self.__sets[key]) : [];
        this.cbExecute(cb, null, result);
        return result as string[];
    }

    // noinspection JSUnusedGlobalSymbols
    public disconnect(): boolean {
        delete RedisClientMock.__clientList[this.__name];
        if (this.__rt) {
            clearTimeout(this.__rt);
            delete this.__rt;
        }
        return true;
    }

    // noinspection JSUnusedGlobalSymbols,JSMethodCanBeStatic
    public config(): boolean {
        return true;
    }

    private cbExecute(cb: any, ...args: any[]): void {
        if (typeof cb === 'function') {
            setTimeout(() => cb(...args), 0);
        }
    }
}

mock('ioredis', {
    default: RedisClientMock,
    Redis: RedisClientMock,
});

export * from 'ioredis';
