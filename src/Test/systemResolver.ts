import assert from 'assert';
import {HostsFile} from '../Lib/HostsFile.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {RCODE} from '../Resolver/RecursiveResolver.js';
import {StubResolverBackend} from '../Resolver/StubResolver.js';
import {SystemResolver} from '../Resolver/SystemResolver.js';
import {test} from './test.js';

const buildResponse = (name: string, type: PacketTypes | number, rcode: number, answers: PacketResource[] = []): Packet => {
    const p = new Packet();
    p.header.qr = 1;
    p.header.aa = 1;
    p.header.rcode = rcode;
    p.questions.push(new PacketQuestion(name, type, PacketClass.IN));
    p.answers = answers;
    return p;
};

const recordingBuilder = (router: (host: string, name: string) => Packet): {
    builder: ({host, port}: {host: string; port?: number;}) => StubResolverBackend;
    targets: string[];
    queries: Array<{host: string; name: string;}>;
} => {
    const targets: string[] = [];
    const queries: Array<{host: string; name: string;}> = [];

    const builder = ({host}: {host: string; port?: number;}): StubResolverBackend => {
        targets.push(host);
        return async(name): Promise<Packet> => {
            queries.push({host: host, name: name});
            return router(host, name);
        };
    };

    return {builder: builder, targets: targets, queries: queries};
};

/* fromConfig — happy path --------------------------------------------- */

test('SystemResolver.fromConfig wires search-path → failover → upstream', async() => {
    const aRec = new PacketResource('host.example.com', new A('10.0.0.1'), PacketClass.IN, 60);
    const {builder, targets, queries} = recordingBuilder((_host, name) => {
        if (name === 'host.example.com') {
            return buildResponse(name, PacketTypes.A, RCODE.NOERROR, [aRec]);
        }
        return buildResponse(name, PacketTypes.A, RCODE.NXDOMAIN);
    });

    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1', '8.8.8.8'],
        search: ['example.com'],
        sortlist: [],
        options: {ndots: 1}
    }, {backend: builder});

    assert.deepStrictEqual(targets, ['1.1.1.1', '8.8.8.8']);

    const response = await resolver.resolve('host', PacketTypes.A);

    assert.strictEqual(response.header.rcode, RCODE.NOERROR);
    assert.strictEqual((response.answers[0].packetType as A).address, '10.0.0.1');

    // search-path expansion: bare 'host' → 'host.example.com' (search) first
    // because dots(0) < ndots(1) — but our search semantics depend on the
    // resolver. Just verify the upstream got the expanded form.
    const names = queries.map((q) => q.name);
    assert.ok(names.includes('host.example.com'));
});

test('SystemResolver.fromConfig consults HostsFile before failover backend', async() => {
    const hosts = HostsFile.parse('192.168.1.5 printer printer.local');

    let upstreamCalls = 0;
    const upstream: StubResolverBackend = async() => {
        upstreamCalls++;
        return buildResponse('x', PacketTypes.A, RCODE.NXDOMAIN);
    };

    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1'],
        search: [],
        sortlist: [],
        options: {}
    }, {hostsFile: hosts, backend: () => upstream});

    const response = await resolver.resolve('printer.local', PacketTypes.A);

    assert.strictEqual(response.header.rcode, RCODE.NOERROR);
    assert.strictEqual((response.answers[0].packetType as A).address, '192.168.1.5');
    assert.strictEqual(upstreamCalls, 0, 'hosts-file hit must not consult upstream');
});

test('SystemResolver.fromConfig falls through to upstream when hosts file misses', async() => {
    const hosts = HostsFile.parse('192.168.1.5 printer');

    const upstreamRec = new PacketResource('cloudflare.com', new A('104.16.0.1'), PacketClass.IN, 60);
    const upstream: StubResolverBackend = async(name) => {
        if (name === 'cloudflare.com') {
            return buildResponse(name, PacketTypes.A, RCODE.NOERROR, [upstreamRec]);
        }
        return buildResponse(name, PacketTypes.A, RCODE.NXDOMAIN);
    };

    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1'],
        search: [],
        sortlist: [],
        options: {}
    }, {hostsFile: hosts, backend: () => upstream});

    const response = await resolver.resolve('cloudflare.com', PacketTypes.A);
    assert.strictEqual((response.answers[0].packetType as A).address, '104.16.0.1');
});

test('SystemResolver.fromConfig fails over to second nameserver on first SERVFAIL', async() => {
    const aRec = new PacketResource('host', new A('10.0.0.1'), PacketClass.IN, 60);
    const {builder} = recordingBuilder((host, name) => {
        if (host === '1.1.1.1') {
            return buildResponse(name, PacketTypes.A, RCODE.SERVFAIL);
        }
        return buildResponse(name, PacketTypes.A, RCODE.NOERROR, [aRec]);
    });

    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1', '8.8.8.8'],
        search: [],
        sortlist: [],
        options: {timeout: 1, attempts: 1}
    }, {backend: builder});

    const response = await resolver.resolve('host.', PacketTypes.A);

    assert.strictEqual(response.header.rcode, RCODE.NOERROR);
    assert.strictEqual((response.answers[0].packetType as A).address, '10.0.0.1');
});

test('SystemResolver.fromConfig throws on empty nameservers', () => {
    assert.throws(() => SystemResolver.fromConfig({
        nameservers: [],
        search: [],
        sortlist: [],
        options: {}
    }), /no `nameserver` entries/);
});

/* stub accessor -------------------------------------------------------- */

test('SystemResolver.stub exposes the underlying StubResolver for inspection', () => {
    const noopBackend: StubResolverBackend = async() => buildResponse('x', PacketTypes.A, RCODE.NXDOMAIN);

    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1'],
        search: ['example.com', 'corp.local'],
        sortlist: [],
        options: {ndots: 2}
    }, {backend: () => noopBackend});

    assert.strictEqual(resolver.stub.ndots, 2);
    assert.deepStrictEqual(resolver.stub.search, ['example.com', 'corp.local']);
    assert.deepStrictEqual(resolver.stub.expand('host'), [
        'host.example.com',
        'host.corp.local',
        'host'
    ]);
});

/* hasSystemFiles ------------------------------------------------------ */

test('SystemResolver.hasSystemFiles reports presence of /etc files', () => {
    // Use definitely-non-existent paths to force false on both.
    const result = SystemResolver.hasSystemFiles({
        resolvConfPath: '/this/path/does/not/exist/resolv.conf',
        hostsPath: '/this/path/does/not/exist/hosts'
    });

    assert.strictEqual(result.resolvConf, false);
    assert.strictEqual(result.hosts, false);
});

/* system() — read-from-disk path -------------------------------------- */

test('SystemResolver.system reads /etc/resolv.conf and survives missing /etc/hosts', async() => {
    // Write a tiny resolv.conf and skip hosts — exercises the
    // hosts-file-tolerance path without hitting the real system files.
    const tmpDir = await import('os').then((os) => os.tmpdir());
    const path = await import('path');
    const fs = await import('fs');

    const confPath = path.join(tmpDir, `resolv-test-${Date.now()}.conf`);
    fs.writeFileSync(confPath, 'nameserver 127.0.0.1\nsearch test.local\n', 'utf8');

    const missingHosts = path.join(tmpDir, `hosts-missing-${Date.now()}`);

    const noopBackend: StubResolverBackend = async() => buildResponse('x', PacketTypes.A, RCODE.NXDOMAIN);

    try {
        const resolver = SystemResolver.system({
            resolvConfPath: confPath,
            hostsPath: missingHosts,
            backend: () => noopBackend
        });

        assert.deepStrictEqual(resolver.stub.search, ['test.local']);
    } finally {
        fs.unlinkSync(confPath);
    }
});

test('SystemResolver.system honours skipHosts:true', async() => {
    const tmpDir = await import('os').then((os) => os.tmpdir());
    const path = await import('path');
    const fs = await import('fs');

    // Write BOTH files — verify skipHosts truly bypasses the hosts layer.
    const confPath = path.join(tmpDir, `resolv-skip-${Date.now()}.conf`);
    const hostsPath = path.join(tmpDir, `hosts-skip-${Date.now()}`);
    fs.writeFileSync(confPath, 'nameserver 127.0.0.1\n', 'utf8');
    fs.writeFileSync(hostsPath, '10.0.0.99 special-host\n', 'utf8');

    let upstreamCalls = 0;
    const upstreamRec = new PacketResource('special-host', new A('1.2.3.4'), PacketClass.IN, 60);
    const upstream: StubResolverBackend = async(name) => {
        upstreamCalls++;
        return buildResponse(name, PacketTypes.A, RCODE.NOERROR, [upstreamRec]);
    };

    try {
        const resolver = SystemResolver.system({
            resolvConfPath: confPath,
            hostsPath: hostsPath,
            skipHosts: true,
            backend: () => upstream
        });

        const response = await resolver.resolve('special-host.', PacketTypes.A);

        assert.strictEqual(upstreamCalls, 1, 'skipHosts must bypass /etc/hosts entirely');
        assert.strictEqual((response.answers[0].packetType as A).address, '1.2.3.4',
            'response came from upstream, not the hosts file');
    } finally {
        fs.unlinkSync(confPath);
        fs.unlinkSync(hostsPath);
    }
});