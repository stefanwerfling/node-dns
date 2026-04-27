import assert from 'assert';
import { DohServer } from '../Server/DohServer.js';
import { get } from './helpers.js';
import { test } from './test.js';
test('server/doh#cors - default', async () => {
    const server = new DohServer();
    const address = await new Promise((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    const { headers } = await get(`http://localhost:${address.port}`);
    assert.equal(headers['access-control-allow-origin'], '*');
    server.close();
});
test('server/doh#cors - no cors', async () => {
    const server = new DohServer({ doh: { cors: false } });
    const address = await new Promise((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    const { headers } = await get(`http://localhost:${address.port}`);
    assert.equal(headers['access-control-allow-origin'], undefined);
    server.close();
});
test('server/doh#cors - cors origin', async () => {
    const server = new DohServer({ doh: { cors: 'some.domain' } });
    const address = await new Promise((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    const { headers } = await get(`http://localhost:${address.port}`);
    assert.equal(headers['access-control-allow-origin'], 'some.domain');
    assert.equal(headers.vary, 'Origin');
    server.close();
});
test('server/doh#cors - cors function', async () => {
    const server = new DohServer({
        doh: {
            cors: async (domain) => {
                if (domain === 'a.domain') {
                    return true;
                }
                else if (domain === 'b.domain') {
                    return false;
                }
                throw new Error(`Unexpected domain: ${domain}`);
            }
        }
    });
    const address = await new Promise((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    let headers = (await get(`http://localhost:${address.port}`, { headers: { origin: 'a.domain' } })).headers;
    assert.equal(headers['access-control-allow-origin'], 'a.domain');
    assert.equal(headers.vary, 'Origin');
    headers = (await get(`http://localhost:${address.port}`, { headers: { origin: 'b.domain' } })).headers;
    assert.equal(headers['access-control-allow-origin'], 'false');
    assert.equal(headers.vary, 'Origin');
    server.close();
});
//# sourceMappingURL=serverDoh.js.map