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
