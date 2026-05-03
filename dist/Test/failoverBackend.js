import assert from 'assert';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { FailoverBackend } from '../Resolver/FailoverBackend.js';
import { RCODE } from '../Resolver/RecursiveResolver.js';
import { test } from './test.js';
const buildResponse = (name, type, rcode, answers = []) => {
    const p = new Packet();
    p.header.qr = 1;
    p.header.rcode = rcode;
    p.questions.push(new PacketQuestion(name, type, PacketClass.IN));
    p.answers = answers;
    return p;
};
const tagged = (id, response) => {
    let calls = 0;
    const backend = async () => {
        calls++;
        return Promise.resolve(response());
    };
    return {
        backend: backend,
        get calls() {
            return calls;
        },
        id: id
    };
};
test('FailoverBackend.combine returns the first non-failover response', async () => {
    const a = tagged('A', () => buildResponse('host', PacketTypes.A, RCODE.NOERROR, [
        new PacketResource('host', new A('10.0.0.1'), PacketClass.IN, 60)
    ]));
    const b = tagged('B', () => buildResponse('host', PacketTypes.A, RCODE.SERVFAIL));
    const failover = FailoverBackend.combine([a.backend, b.backend], { timeoutMs: 0, attempts: 1 });
    const response = await failover('host', PacketTypes.A, PacketClass.IN);
    assert.strictEqual(response.header.rcode, RCODE.NOERROR);
    assert.strictEqual(a.calls, 1, 'first backend used');
    assert.strictEqual(b.calls, 0, 'second backend untouched');
});
test('FailoverBackend.combine fails over from SERVFAIL to a healthy backend', async () => {
    const a = tagged('A', () => buildResponse('host', PacketTypes.A, RCODE.SERVFAIL));
    const b = tagged('B', () => buildResponse('host', PacketTypes.A, RCODE.NOERROR, [
        new PacketResource('host', new A('10.0.0.2'), PacketClass.IN, 60)
    ]));
    const failover = FailoverBackend.combine([a.backend, b.backend], { timeoutMs: 0, attempts: 1 });
    const response = await failover('host', PacketTypes.A, PacketClass.IN);
    assert.strictEqual(response.header.rcode, RCODE.NOERROR);
    assert.strictEqual(response.answers[0].packetType.address, '10.0.0.2');
    assert.strictEqual(a.calls, 1);
    assert.strictEqual(b.calls, 1);
});
test('FailoverBackend.combine fails over on thrown errors (timeout/network)', async () => {
    const a = tagged('A', () => {
        throw new Error('ECONNREFUSED');
    });
    const b = tagged('B', () => buildResponse('host', PacketTypes.A, RCODE.NOERROR, [
        new PacketResource('host', new A('10.0.0.2'), PacketClass.IN, 60)
    ]));
    const failover = FailoverBackend.combine([a.backend, b.backend], { timeoutMs: 0, attempts: 1 });
    const response = await failover('host', PacketTypes.A, PacketClass.IN);
    assert.strictEqual(response.header.rcode, RCODE.NOERROR);
    assert.strictEqual(a.calls, 1);
    assert.strictEqual(b.calls, 1);
});
test('FailoverBackend.combine returns NXDOMAIN without trying next backend', async () => {
    const a = tagged('A', () => buildResponse('host', PacketTypes.A, RCODE.NXDOMAIN));
    const b = tagged('B', () => buildResponse('host', PacketTypes.A, RCODE.NOERROR));
    const failover = FailoverBackend.combine([a.backend, b.backend], { timeoutMs: 0, attempts: 1 });
    const response = await failover('host', PacketTypes.A, PacketClass.IN);
    assert.strictEqual(response.header.rcode, RCODE.NXDOMAIN, 'definitive answer — no failover');
    assert.strictEqual(b.calls, 0, 'next backend untouched on NXDOMAIN');
});
test('FailoverBackend.combine returns REFUSED without trying next backend', async () => {
    const a = tagged('A', () => buildResponse('host', PacketTypes.A, RCODE.REFUSED));
    const b = tagged('B', () => buildResponse('host', PacketTypes.A, RCODE.NOERROR));
    const failover = FailoverBackend.combine([a.backend, b.backend], { timeoutMs: 0, attempts: 1 });
    const response = await failover('host', PacketTypes.A, PacketClass.IN);
    assert.strictEqual(response.header.rcode, RCODE.REFUSED, 'REFUSED is definitive in default predicate');
    assert.strictEqual(b.calls, 0);
});
test('FailoverBackend.combine retries each backend up to `attempts` times before failover', async () => {
    let attemptOnA = 0;
    const a = async () => {
        attemptOnA++;
        return buildResponse('host', PacketTypes.A, RCODE.SERVFAIL);
    };
    const b = tagged('B', () => buildResponse('host', PacketTypes.A, RCODE.NOERROR));
    const failover = FailoverBackend.combine([a, b.backend], { timeoutMs: 0, attempts: 3 });
    await failover('host', PacketTypes.A, PacketClass.IN);
    assert.strictEqual(attemptOnA, 3, 'A retried 3 times on SERVFAIL');
    assert.strictEqual(b.calls, 1, 'B reached after A exhausted');
});
test('FailoverBackend.combine returns last response when every backend×attempt fails', async () => {
    const a = tagged('A', () => buildResponse('a-host', PacketTypes.A, RCODE.SERVFAIL));
    const b = tagged('B', () => buildResponse('b-host', PacketTypes.A, RCODE.SERVFAIL));
    const failover = FailoverBackend.combine([a.backend, b.backend], { timeoutMs: 0, attempts: 2 });
    const response = await failover('host', PacketTypes.A, PacketClass.IN);
    assert.strictEqual(response.header.rcode, RCODE.SERVFAIL);
    assert.strictEqual(response.questions[0].name, 'b-host', 'last response wins on full exhaustion');
    assert.strictEqual(a.calls, 2);
    assert.strictEqual(b.calls, 2);
});
test('FailoverBackend.combine throws last error when every backend×attempt threw', async () => {
    const a = async () => {
        throw new Error('first');
    };
    const b = async () => {
        throw new Error('last');
    };
    const failover = FailoverBackend.combine([a, b], { timeoutMs: 0, attempts: 1 });
    await assert.rejects(failover('host', PacketTypes.A, PacketClass.IN), /last/);
});
test('FailoverBackend.combine times out a slow backend and fails over', async () => {
    const a = () => new Promise((r) => {
        setTimeout(() => r(buildResponse('host', PacketTypes.A, RCODE.NOERROR)), 1000);
    });
    const b = tagged('B', () => buildResponse('host', PacketTypes.A, RCODE.NOERROR, [
        new PacketResource('host', new A('10.0.0.2'), PacketClass.IN, 60)
    ]));
    const failover = FailoverBackend.combine([a, b.backend], { timeoutMs: 30, attempts: 1 });
    const start = Date.now();
    const response = await failover('host', PacketTypes.A, PacketClass.IN);
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 200, `failover should be fast after timeout, was ${elapsed}ms`);
    assert.strictEqual(response.answers[0].packetType.address, '10.0.0.2');
    assert.strictEqual(b.calls, 1);
});
test('FailoverBackend.combine rotates the starting backend when rotate:true', async () => {
    const calls = [];
    const a = async () => {
        calls.push('A');
        return buildResponse('host', PacketTypes.A, RCODE.NOERROR);
    };
    const b = async () => {
        calls.push('B');
        return buildResponse('host', PacketTypes.A, RCODE.NOERROR);
    };
    const c = async () => {
        calls.push('C');
        return buildResponse('host', PacketTypes.A, RCODE.NOERROR);
    };
    const failover = FailoverBackend.combine([a, b, c], { timeoutMs: 0, rotate: true });
    await failover('h', PacketTypes.A, PacketClass.IN);
    await failover('h', PacketTypes.A, PacketClass.IN);
    await failover('h', PacketTypes.A, PacketClass.IN);
    await failover('h', PacketTypes.A, PacketClass.IN);
    assert.deepStrictEqual(calls, ['A', 'B', 'C', 'A'], 'cursor advances per call when rotate:true');
});
test('FailoverBackend.combine without rotate always starts at index 0', async () => {
    const calls = [];
    const a = async () => {
        calls.push('A');
        return buildResponse('host', PacketTypes.A, RCODE.NOERROR);
    };
    const b = async () => {
        calls.push('B');
        return buildResponse('host', PacketTypes.A, RCODE.NOERROR);
    };
    const failover = FailoverBackend.combine([a, b], { timeoutMs: 0 });
    await failover('h', PacketTypes.A, PacketClass.IN);
    await failover('h', PacketTypes.A, PacketClass.IN);
    assert.deepStrictEqual(calls, ['A', 'A'], 'always start at A when rotate is off');
});
test('FailoverBackend.combine honours a custom shouldFailover predicate', async () => {
    const a = tagged('A', () => buildResponse('host', PacketTypes.A, RCODE.REFUSED));
    const b = tagged('B', () => buildResponse('host', PacketTypes.A, RCODE.NOERROR));
    const failover = FailoverBackend.combine([a.backend, b.backend], {
        timeoutMs: 0,
        attempts: 1,
        shouldFailover: (r) => {
            if (r instanceof Error) {
                return true;
            }
            return r.header.rcode === RCODE.SERVFAIL || r.header.rcode === RCODE.REFUSED;
        }
    });
    const response = await failover('host', PacketTypes.A, PacketClass.IN);
    assert.strictEqual(response.header.rcode, RCODE.NOERROR);
    assert.strictEqual(b.calls, 1, 'predicate forwarded through to next backend');
});
test('FailoverBackend.combine rejects an empty backend list synchronously', () => {
    assert.throws(() => FailoverBackend.combine([], {}), /at least one backend/);
});
test('FailoverBackend.fromConfig wires nameservers/timeout/attempts/rotate from resolv.conf', async () => {
    const built = [];
    const calls = [];
    const failover = FailoverBackend.fromConfig({
        nameservers: ['1.1.1.1', '8.8.8.8'],
        search: [],
        sortlist: [],
        options: { timeout: 1, attempts: 2, rotate: true }
    }, ({ host }) => {
        built.push(host);
        return async () => {
            calls.push(host);
            return buildResponse('host', PacketTypes.A, RCODE.SERVFAIL);
        };
    });
    assert.ok(failover !== null);
    assert.deepStrictEqual(built, ['1.1.1.1', '8.8.8.8'], 'one backend per nameserver, in order');
    if (failover === null) {
        return;
    }
    await failover('host', PacketTypes.A, PacketClass.IN);
    await failover('host', PacketTypes.A, PacketClass.IN);
    const c1 = calls.filter((c) => c === '1.1.1.1').length;
    const c2 = calls.filter((c) => c === '8.8.8.8').length;
    assert.strictEqual(c1, 4);
    assert.strictEqual(c2, 4);
    assert.strictEqual(calls[0], '1.1.1.1', 'first call starts at index 0');
    assert.strictEqual(calls[4], '8.8.8.8', 'second call rotates to index 1');
});
test('FailoverBackend.fromConfig returns null when nameservers list is empty', () => {
    const failover = FailoverBackend.fromConfig({
        nameservers: [],
        search: [],
        sortlist: [],
        options: {}
    }, () => {
        throw new Error('builder must not be called when no nameservers');
    });
    assert.strictEqual(failover, null);
});
//# sourceMappingURL=failoverBackend.js.map