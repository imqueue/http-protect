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
import { beforeEach, afterEach, describe } from 'mocha';
import { expect } from 'chai';
import HttpProtect, { Request, VerificationStatus } from '../../src';

function ipRequest(ip: string): Request {
    return { headers: { 'x-forwarded-for': ip } } as Request;
}

describe('HttpProtect', function () {
    this.timeout(5000);

    it('should be a class', () => {
        expect(typeof HttpProtect).to.be.equal('function');
    });

    it('should be constructable', () => {
        expect(() => {
            const protector = new HttpProtect();
            protector.destroy();
        }).not.to.throw();
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
                const ip = `127.0.0.${ i }`;
                const req = ipRequest(ip);

                for (let j = 0; j < 1001; j++) {
                    await protector.verify(req);
                }
            }

            for (let i = 13; i < 23; i++) {
                const ip = `127.0.0.${ i }`;
                const req = ipRequest(ip);

                for (let j = 0; j < 998; j++) {
                    await protector.verify(req);
                }
            }

            const banned = await protector.bannedNetworks();

            expect(banned.includes('127.0.0.1')).to.be.false;
            expect(banned.includes('127.0.0.2')).to.be.true;
            expect(banned.includes('127.0.0.13')).to.be.false;

            await protector.isLimited('127.0.0.13')
            .then((isLimited) => {
                expect(isLimited).to.be.true;
            });

            await protector.verify(ipRequest('127.0.0.10'))
            .then((result) => {
                expect(result.status).to.be.equal(VerificationStatus.BANNED);
            });

            await protector.verify(ipRequest('127.0.0.15'))
            .then((result) => {
                expect(result.status).to.be.equal(VerificationStatus.LIMITED);
            });

            await protector.verify(ipRequest('127.0.0.1'))
            .then((result) => {
                expect(result.status).to.be.equal(VerificationStatus.SAFE);
            });
        });
    });
});
