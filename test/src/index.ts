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
import { beforeEach, afterEach, describe } from 'mocha';
import { expect } from 'chai';
import HttpProtect, { Request, VerificationStatus } from '../../src';

function ipRequest(ip: string): Request {
    return { headers: { 'x-forwarded-for': ip } } as Request;
}

describe('HttpProtect', () => {
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
