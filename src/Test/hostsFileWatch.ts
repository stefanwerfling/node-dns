import assert from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {HostsFile} from '../Lib/HostsFile.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {RCODE} from '../Resolver/RecursiveResolver.js';
import {StubResolverBackend} from '../Resolver/StubResolver.js';
import {SystemResolver} from '../Resolver/SystemResolver.js';
import {test} from './test.js';

const noopBackend: StubResolverBackend = async(name, type, cls): Promise<Packet> => {
    const p = new Packet();
    p.header.qr = 1;
    p.header.rcode = RCODE.NXDOMAIN;
    p.questions.push(new PacketQuestion(name, type, cls));
    return p;
};

const writeTmp = (content: string): string => {
    const tmp = path.join(os.tmpdir(), `dns2ts-hosts-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    fs.writeFileSync(tmp, content, 'utf8');
    return tmp;
};

const waitForReload = (file: HostsFile, expectName: string, timeoutMs: number = 1500): Promise<void> => {
    return new Promise<void>((resolve, reject) => {
        const start = Date.now();
        const tick = (): void => {
            if (file.lookup(expectName, PacketTypes.A).kind === 'match') {
                resolve();
                return;
            }

            if (Date.now() - start > timeoutMs) {
                reject(new Error(`waitForReload: ${expectName} never appeared after ${timeoutMs}ms`));
                return;
            }

            setTimeout(tick, 20);
        };

        tick();
    });
};

/* reload() --------------------------------------------------------- */

test('HostsFile.reload picks up newly-added entries from disk', () => {
    const tmp = writeTmp('10.0.0.1 alpha\n');

    try {
        const hosts = HostsFile.fromFile(tmp);
        assert.equal(hosts.lookup('alpha', PacketTypes.A).kind, 'match');
        assert.equal(hosts.lookup('beta', PacketTypes.A).kind, 'miss');

        fs.appendFileSync(tmp, '10.0.0.2 beta\n', 'utf8');
        hosts.reload();

        assert.equal(hosts.lookup('beta', PacketTypes.A).kind, 'match');
    } finally {
        fs.unlinkSync(tmp);
    }
});

test('HostsFile.reload drops entries removed from disk', () => {
    const tmp = writeTmp('10.0.0.1 alpha\n10.0.0.2 beta\n');

    try {
        const hosts = HostsFile.fromFile(tmp);
        assert.equal(hosts.lookup('beta', PacketTypes.A).kind, 'match');

        fs.writeFileSync(tmp, '10.0.0.1 alpha\n', 'utf8');
        hosts.reload();

        assert.equal(hosts.lookup('beta', PacketTypes.A).kind, 'miss');
        assert.equal(hosts.lookup('alpha', PacketTypes.A).kind, 'match');
    } finally {
        fs.unlinkSync(tmp);
    }
});

test('HostsFile.reload throws when no source path is known', () => {
    const hosts = HostsFile.parse('10.0.0.1 alpha\n');
    assert.equal(hosts.sourcePath, null);
    assert.throws(() => hosts.reload(), /no source path/);
});

test('HostsFile.reload accepts explicit path and remembers it', () => {
    const tmp = writeTmp('10.0.0.5 boot\n');

    try {
        const hosts = HostsFile.parse('');
        hosts.reload(tmp);
        assert.equal(hosts.lookup('boot', PacketTypes.A).kind, 'match');
        assert.equal(hosts.sourcePath, tmp);
    } finally {
        fs.unlinkSync(tmp);
    }
});

test('HostsFile.asResolverBackend closure sees post-reload entries', async() => {
    const tmp = writeTmp('10.0.0.1 alpha\n');

    try {
        const hosts = HostsFile.fromFile(tmp);
        const backend = hosts.asResolverBackend(noopBackend);

        const r1 = await backend('beta', PacketTypes.A, PacketClass.IN);
        assert.equal(r1.header.rcode, RCODE.NXDOMAIN, 'beta misses, falls through to noop NXDOMAIN');

        fs.appendFileSync(tmp, '10.0.0.2 beta\n', 'utf8');
        hosts.reload();

        const r2 = await backend('beta', PacketTypes.A, PacketClass.IN);
        assert.equal(r2.header.rcode, RCODE.NOERROR);
        assert.equal((r2.answers[0].packetType as A).address, '10.0.0.2');
    } finally {
        fs.unlinkSync(tmp);
    }
});

/* watch() ---------------------------------------------------------- */

test('HostsFile.watch reloads on append', async() => {
    const tmp = writeTmp('10.0.0.1 alpha\n');
    const hosts = HostsFile.fromFile(tmp);
    const handle = hosts.watch({debounceMs: 20});

    try {
        assert.equal(hosts.lookup('beta', PacketTypes.A).kind, 'miss');

        fs.appendFileSync(tmp, '10.0.0.2 beta\n', 'utf8');
        await waitForReload(hosts, 'beta');
        assert.equal(hosts.lookup('beta', PacketTypes.A).kind, 'match');
    } finally {
        handle.close();
        fs.unlinkSync(tmp);
    }
});

test('HostsFile.watch debounces rapid edits into one reload', async() => {
    const tmp = writeTmp('10.0.0.1 alpha\n');
    const hosts = HostsFile.fromFile(tmp);

    let reloads = 0;
    const handle = hosts.watch({
        debounceMs: 80,
        onReload: (): void => {
            reloads++;
        }
    });

    try {
        // Fire 5 quick appends within the debounce window.
        for (let i = 0; i < 5; i++) {
            fs.appendFileSync(tmp, `10.0.0.${i + 2} host${i}\n`, 'utf8');
        }

        await waitForReload(hosts, 'host4');
        await new Promise<void>((resolve) => setTimeout(resolve, 150));

        assert.ok(reloads >= 1, 'at least one reload fired');
        assert.ok(reloads <= 2, `at most a couple of reloads — got ${reloads}`);
        for (let i = 0; i < 5; i++) {
            assert.equal(hosts.lookup(`host${i}`, PacketTypes.A).kind, 'match');
        }
    } finally {
        handle.close();
        fs.unlinkSync(tmp);
    }
});

test('HostsFile.watch handles editor write-and-rename (vim/emacs pattern)', async() => {
    const tmp = writeTmp('10.0.0.1 alpha\n');
    const hosts = HostsFile.fromFile(tmp);
    const handle = hosts.watch({debounceMs: 30});

    try {
        assert.equal(hosts.lookup('gamma', PacketTypes.A).kind, 'miss');

        // Simulate vim's "write to temp + rename over original".
        const tmpSwap = `${tmp}.swap`;
        fs.writeFileSync(tmpSwap, '10.0.0.1 alpha\n10.0.0.3 gamma\n', 'utf8');
        fs.renameSync(tmpSwap, tmp);

        await waitForReload(hosts, 'gamma');
        assert.equal(hosts.lookup('gamma', PacketTypes.A).kind, 'match');

        // Verify the re-established watcher still fires on subsequent edits.
        fs.appendFileSync(tmp, '10.0.0.4 delta\n', 'utf8');
        await waitForReload(hosts, 'delta');
        assert.equal(hosts.lookup('delta', PacketTypes.A).kind, 'match');
    } finally {
        handle.close();
        fs.unlinkSync(tmp);
    }
});

test('HostsFile.watch reloadNow() reloads synchronously and bypasses debounce', () => {
    const tmp = writeTmp('10.0.0.1 alpha\n');
    const hosts = HostsFile.fromFile(tmp);
    const handle = hosts.watch({debounceMs: 10_000});

    try {
        fs.appendFileSync(tmp, '10.0.0.2 beta\n', 'utf8');
        // Without reloadNow we'd be stuck waiting 10s for the debounce.
        handle.reloadNow();
        assert.equal(hosts.lookup('beta', PacketTypes.A).kind, 'match');
    } finally {
        handle.close();
        fs.unlinkSync(tmp);
    }
});

test('HostsFile.watch close() is idempotent and stops further reloads', async() => {
    const tmp = writeTmp('10.0.0.1 alpha\n');
    const hosts = HostsFile.fromFile(tmp);

    let reloads = 0;
    const handle = hosts.watch({
        debounceMs: 20,
        onReload: (): void => {
            reloads++;
        }
    });

    try {
        handle.close();
        handle.close(); // idempotent
        assert.equal(handle.closed, true);

        fs.appendFileSync(tmp, '10.0.0.2 beta\n', 'utf8');
        await new Promise<void>((resolve) => setTimeout(resolve, 100));

        assert.equal(reloads, 0, 'no reload after close');
        assert.equal(hosts.lookup('beta', PacketTypes.A).kind, 'miss');
    } finally {
        fs.unlinkSync(tmp);
    }
});

test('HostsFile.watch routes reload errors to onError', async() => {
    const tmp = writeTmp('10.0.0.1 alpha\n');
    const hosts = HostsFile.fromFile(tmp);

    const errors: NodeJS.ErrnoException[] = [];
    const handle = hosts.watch({
        debounceMs: 20,
        onError: (err): void => {
            errors.push(err);
        }
    });

    try {
        // Delete the file out from under the watcher and trigger an event.
        fs.unlinkSync(tmp);

        // fs.watch may or may not fire on the unlink itself — force a
        // reload to hit the error path deterministically.
        handle.reloadNow();

        await new Promise<void>((resolve) => setTimeout(resolve, 50));
        assert.ok(errors.length >= 1, 'onError fired on missing file');
        assert.equal(errors[0].code, 'ENOENT');
    } finally {
        handle.close();
        // tmp already deleted
    }
});

test('HostsFile.watch throws when no path is known', () => {
    const hosts = HostsFile.parse('10.0.0.1 alpha\n');
    assert.throws(() => hosts.watch(), /no path/);
});

/* SystemResolver wiring -------------------------------------------- */

test('SystemResolver.watchHosts:true installs a handle on .hostsWatch', async() => {
    const tmp = writeTmp('10.0.0.1 alpha\n');

    try {
        const hosts = HostsFile.fromFile(tmp);
        const resolver = SystemResolver.fromConfig({
            nameservers: ['1.1.1.1'],
            search: [],
            sortlist: [],
            options: {}
        }, {hostsFile: hosts, backend: () => noopBackend, watchHosts: true});

        try {
            assert.ok(resolver.hostsWatch !== null);
            assert.equal(resolver.hostsWatch!.path, tmp);

            fs.appendFileSync(tmp, '10.0.0.2 beta\n', 'utf8');
            await waitForReload(hosts, 'beta');

            const r = await resolver.resolve('beta', PacketTypes.A);
            assert.equal((r.answers[0].packetType as A).address, '10.0.0.2');
        } finally {
            resolver.close();
        }

        assert.equal(resolver.hostsWatch!.closed, true);
    } finally {
        fs.unlinkSync(tmp);
    }
});

test('SystemResolver.watchHosts forwards HostsFileWatchOptions', async() => {
    const tmp = writeTmp('10.0.0.1 alpha\n');

    try {
        const hosts = HostsFile.fromFile(tmp);
        let reloadCallbackFired = 0;

        const resolver = SystemResolver.fromConfig({
            nameservers: ['1.1.1.1'],
            search: [],
            sortlist: [],
            options: {}
        }, {
            hostsFile: hosts,
            backend: () => noopBackend,
            watchHosts: {
                debounceMs: 20,
                onReload: (): void => {
                    reloadCallbackFired++;
                }
            }
        });

        try {
            fs.appendFileSync(tmp, '10.0.0.2 beta\n', 'utf8');
            await waitForReload(hosts, 'beta');
            await new Promise<void>((resolve) => setTimeout(resolve, 80));
            assert.ok(reloadCallbackFired >= 1, 'caller-provided onReload fired');
        } finally {
            resolver.close();
        }
    } finally {
        fs.unlinkSync(tmp);
    }
});

test('SystemResolver.watchHosts is a no-op without a hosts file', () => {
    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1'],
        search: [],
        sortlist: [],
        options: {}
    }, {backend: () => noopBackend, watchHosts: true});

    assert.equal(resolver.hostsWatch, null, 'nothing to watch without a hosts file');
    resolver.close();
});

test('SystemResolver.close() is idempotent and safe without a watch', () => {
    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1'],
        search: [],
        sortlist: [],
        options: {}
    }, {backend: () => noopBackend});

    resolver.close();
    resolver.close();
});