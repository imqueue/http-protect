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
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import './mocks/index.js';
import HttpProtect, { type Request, VerificationStatus } from '../src/index.js';

function ipRequest(ip: string): Request {
    return { headers: { 'x-forwarded-for': ip } } as Request;
}

describe('HttpProtect', () => {
    it('should be a class', () => {
        assert.equal(typeof HttpProtect, 'function');
    });

    it('should be constructable', () => {
        assert.doesNotThrow(() => {
            const protector = new HttpProtect();
            protector.destroy();
        });
    });

    describe('verify()', () => {
        let protector: HttpProtect;

        beforeEach(() => {
            protector = new HttpProtect();
        });

        afterEach(() => {
            protector.destroy();
        });

        it('should ban, limit & verify properly', async () => {
            for (let i = 2; i < 12; i++) {
                const ip = `127.0.0.${i}`;
                const req = ipRequest(ip);

                for (let j = 0; j < 1001; j++) {
                    await protector.verify(req);
                }
            }

            for (let i = 13; i < 23; i++) {
                const ip = `127.0.0.${i}`;
                const req = ipRequest(ip);

                for (let j = 0; j < 998; j++) {
                    await protector.verify(req);
                }
            }

            const banned = await protector.bannedNetworks();

            assert.equal(banned.includes('127.0.0.1'), false);
            assert.equal(banned.includes('127.0.0.2'), true);
            assert.equal(banned.includes('127.0.0.13'), false);

            await protector.isLimited('127.0.0.13').then(isLimited => {
                assert.equal(isLimited, true);
            });

            await protector.verify(ipRequest('127.0.0.10')).then(result => {
                assert.equal(result.status, VerificationStatus.BANNED);
            });

            await protector.verify(ipRequest('127.0.0.15')).then(result => {
                assert.equal(result.status, VerificationStatus.LIMITED);
            });

            await protector.verify(ipRequest('127.0.0.1')).then(result => {
                assert.equal(result.status, VerificationStatus.SAFE);
            });
        });
    });
});

describe('HttpProtect: extended behavior', () => {
    function fakeResponse() {
        const state = {
            statusCode: 0,
            headers: {} as Record<string, string>,
            body: '',
            ended: false,
        };

        return {
            state,
            status(code: number) {
                state.statusCode = code;
            },
            setHeader(name: string, value: string) {
                state.headers[name.toLowerCase()] = value;
            },
            send(body: string) {
                state.body = body;
            },
            end() {
                state.ended = true;
            },
        };
    }

    describe('safeNetworks', () => {
        it('should never limit or ban safe networks', async () => {
            const protector = new HttpProtect({
                safeNetworks: ['10.0.0.0/8'],
            });
            const req = ipRequest('10.1.2.3');

            for (let i = 0; i < 2000; i++) {
                const result = await protector.verify(req);

                assert.equal(result.status, VerificationStatus.SAFE);
            }

            assert.equal(await protector.isBanned('10.1.2.3'), false);
            protector.destroy();
        });
    });

    describe('getClientIp override', () => {
        it('should default to the request-ip resolver', async () => {
            const protector = new HttpProtect();

            assert.equal(
                protector.getClientIp(ipRequest('8.7.6.5')),
                '8.7.6.5',
            );
            protector.destroy();
        });

        it('should use a custom resolver when provided', async () => {
            const calls: any[] = [];
            const protector = new HttpProtect({
                getClientIp: req => {
                    calls.push(req);

                    // e.g. a trust-aware resolver reading a specific header
                    return (req.headers?.['x-real-ip'] as string) || null;
                },
            });

            const req = {
                headers: {
                    // spoofed forwarded header must be ignored by the override
                    'x-forwarded-for': '1.1.1.1',
                    'x-real-ip': '3.3.3.3',
                },
            } as any;

            for (let i = 0; i < 1001; i++) {
                await protector.verify(req);
            }

            // ban lands on the resolver-provided IP, not the spoofed header
            assert.equal(await protector.isBanned('3.3.3.3'), true);
            assert.equal(await protector.isBanned('1.1.1.1'), false);
            assert.ok(calls.length > 0, 'custom resolver must be called');
            protector.destroy();
        });
    });

    describe('isBanned()', () => {
        it('should reflect ban state of a specific ip', async () => {
            const protector = new HttpProtect();
            const req = ipRequest('4.4.4.4');

            for (let i = 0; i < 1001; i++) {
                await protector.verify(req);
            }

            assert.equal(await protector.isBanned('4.4.4.4'), true);
            assert.equal(await protector.isBanned('5.5.5.5'), false);
            protector.destroy();
        });
    });

    describe('middleware()', () => {
        it('should call next() for a safe request', async () => {
            const protector = new HttpProtect();
            const res = fakeResponse();
            let nextCalled = false;

            await protector.middleware()(
                ipRequest('6.6.6.6'),
                res as any,
                () => {
                    nextCalled = true;
                },
            );

            assert.equal(nextCalled, true);
            assert.equal(res.state.ended, false);
            protector.destroy();
        });

        it('should end a banned request with 418', async () => {
            const protector = new HttpProtect();
            const req = ipRequest('7.7.7.7');

            for (let i = 0; i < 1001; i++) {
                await protector.verify(req);
            }

            const res = fakeResponse();
            let nextCalled = false;

            await protector.middleware()(req, res as any, () => {
                nextCalled = true;
            });

            assert.equal(nextCalled, false);
            assert.equal(res.state.statusCode, 418);
            assert.equal(res.state.ended, true);
            protector.destroy();
        });
    });

    describe('jsonMiddleware()', () => {
        it('should respond with a json error for limited requests', async () => {
            const protector = new HttpProtect();
            const req = ipRequest('8.8.4.4');

            for (let i = 0; i < 300; i++) {
                await protector.verify(req);
            }

            const res = fakeResponse();

            await protector.jsonMiddleware()(req, res as any, () => undefined);

            assert.equal(res.state.statusCode, 429);
            assert.equal(res.state.headers['content-type'], 'application/json');
            assert.equal(JSON.parse(res.state.body).error.code, 429);
            protector.destroy();
        });
    });

    describe('textMiddleware()', () => {
        it('should respond with a plain-text error for banned requests', async () => {
            const protector = new HttpProtect();
            const req = ipRequest('9.9.9.9');

            for (let i = 0; i < 1001; i++) {
                await protector.verify(req);
            }

            const res = fakeResponse();

            await protector.textMiddleware()(req, res as any, () => undefined);

            assert.equal(res.state.statusCode, 418);
            assert.equal(res.state.headers['content-type'], 'text/plain');
            assert.ok(res.state.body.startsWith('418'));
            protector.destroy();
        });
    });
});
