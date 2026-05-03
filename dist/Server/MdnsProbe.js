import { Buffer } from 'buffer';
import dgram from 'dgram';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { MDNS_CACHE_FLUSH_BIT, MDNS_MULTICAST_IPV4, MDNS_MULTICAST_IPV6, MDNS_PORT, MDNS_QU_BIT } from '../Client/MdnsClient.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
export class MdnsProbe {
    static async claim(options) {
        const resolved = MdnsProbe._resolveOptions(options);
        return MdnsProbe._run(resolved);
    }
    static canonicalRecordKey(record) {
        const writer = new BufferWriter();
        writer.write(record.packetType.type, 16);
        writer.write(record.class & ~MDNS_CACHE_FLUSH_BIT, 16);
        const rdataWriter = new BufferWriter();
        const out = record.packetType.encode(record, rdataWriter);
        writer.writeBuffer(out);
        return writer.toBuffer();
    }
    static compareRecordSets(a, b) {
        const ka = a.map((r) => MdnsProbe.canonicalRecordKey(r)).sort(Buffer.compare);
        const kb = b.map((r) => MdnsProbe.canonicalRecordKey(r)).sort(Buffer.compare);
        const lim = Math.min(ka.length, kb.length);
        for (let i = 0; i < lim; i++) {
            const cmp = Buffer.compare(ka[i], kb[i]);
            if (cmp !== 0) {
                return cmp > 0 ? 1 : -1;
            }
        }
        if (ka.length === kb.length) {
            return 0;
        }
        return ka.length > kb.length ? 1 : -1;
    }
    static _resolveOptions(options) {
        if (!Array.isArray(options.records) || options.records.length === 0) {
            throw new Error('MdnsProbe.claim: at least one tentative record is required');
        }
        const name = options.records[0].name;
        for (const r of options.records) {
            if (r.name !== name) {
                throw new Error(`MdnsProbe.claim: all tentative records must share one owner name (got "${r.name}" and "${name}")`);
            }
        }
        const family = options.family ?? 'udp4';
        const multicastAddr = options.multicastAddr
            ?? (family === 'udp6' ? MDNS_MULTICAST_IPV6 : MDNS_MULTICAST_IPV4);
        const port = options.port ?? MDNS_PORT;
        return {
            records: options.records,
            name: name,
            multicastAddr: multicastAddr,
            port: port,
            bindPort: options.bindPort ?? port,
            family: family,
            interfaceAddress: options.interfaceAddress,
            joinMulticastGroup: options.joinMulticastGroup ?? MdnsProbe._isMulticast(multicastAddr),
            initialJitterMs: options.initialJitterMs ?? 250,
            probeIntervalMs: options.probeIntervalMs ?? 250,
            probeAttempts: options.probeAttempts ?? 3,
            announceAttempts: options.announceAttempts ?? 2,
            announceIntervalMs: options.announceIntervalMs ?? 1000,
            random: options.random ?? Math.random
        };
    }
    static _run(opts) {
        return new Promise((resolve, reject) => {
            const socket = dgram.createSocket({ type: opts.family, reuseAddr: true });
            let settled = false;
            let timer = null;
            const ourKeys = opts.records.map((r) => MdnsProbe.canonicalRecordKey(r)).sort(Buffer.compare);
            const cleanup = () => {
                if (timer !== null) {
                    clearTimeout(timer);
                    timer = null;
                }
                try {
                    socket.close();
                }
                catch {
                }
            };
            const finish = (err, result) => {
                if (settled) {
                    return;
                }
                settled = true;
                cleanup();
                if (err) {
                    reject(err);
                }
                else if (result !== undefined) {
                    resolve(result);
                }
            };
            const wait = (ms) => new Promise((r) => {
                timer = setTimeout(() => {
                    timer = null;
                    r();
                }, ms);
                timer.unref?.();
            });
            socket.on('error', (err) => finish(err));
            socket.on('message', (msg, rinfo) => {
                if (settled) {
                    return;
                }
                let parsed;
                try {
                    parsed = Packet.parse(msg);
                }
                catch {
                    return;
                }
                const conflict = MdnsProbe._classify(parsed, opts, ourKeys);
                if (conflict !== null) {
                    finish(null, {
                        result: 'conflict',
                        conflictRecord: conflict.record,
                        conflictSource: { address: rinfo.address, port: rinfo.port }
                    });
                }
            });
            const startProbe = async () => {
                try {
                    if (opts.joinMulticastGroup) {
                        try {
                            if (opts.interfaceAddress !== undefined) {
                                socket.addMembership(opts.multicastAddr, opts.interfaceAddress);
                            }
                            else {
                                socket.addMembership(opts.multicastAddr);
                            }
                        }
                        catch {
                        }
                    }
                    await wait(Math.floor(opts.random() * opts.initialJitterMs));
                    if (settled) {
                        return;
                    }
                    for (let i = 0; i < opts.probeAttempts && !settled; i++) {
                        await MdnsProbe._sendProbe(socket, opts);
                        if (settled) {
                            return;
                        }
                        await wait(opts.probeIntervalMs);
                    }
                    if (settled) {
                        return;
                    }
                    for (let i = 0; i < opts.announceAttempts && !settled; i++) {
                        if (i > 0) {
                            await wait(opts.announceIntervalMs);
                            if (settled) {
                                return;
                            }
                        }
                        await MdnsProbe._sendAnnouncement(socket, opts);
                    }
                    finish(null, { result: 'claimed' });
                }
                catch (err) {
                    finish(err instanceof Error ? err : new Error(String(err)));
                }
            };
            socket.bind(opts.bindPort, opts.interfaceAddress, () => {
                startProbe();
            });
        });
    }
    static _classify(packet, opts, ourKeys) {
        if (packet.header.qr === 1) {
            for (const r of [...packet.answers, ...packet.authorities]) {
                if (!MdnsProbe._nameEquals(r.name, opts.name)) {
                    continue;
                }
                const key = MdnsProbe.canonicalRecordKey(r);
                if (!MdnsProbe._keyInSet(key, ourKeys)) {
                    return { record: r };
                }
            }
            return null;
        }
        const asksForOurName = packet.questions.some((q) => MdnsProbe._nameEquals(q.name, opts.name));
        if (!asksForOurName) {
            return null;
        }
        const peerAuthForName = packet.authorities.filter((r) => MdnsProbe._nameEquals(r.name, opts.name));
        if (peerAuthForName.length === 0) {
            return null;
        }
        const cmp = MdnsProbe.compareRecordSets(opts.records, peerAuthForName);
        if (cmp >= 0) {
            return null;
        }
        return { record: peerAuthForName[0] };
    }
    static _sendProbe(socket, opts) {
        const probe = new Packet();
        probe.header.id = 0;
        probe.header.qr = 0;
        probe.header.rd = 0;
        probe.questions.push(new PacketQuestion(opts.name, PacketTypes.ANY, PacketClass.IN | MDNS_QU_BIT));
        probe.authorities = opts.records.slice();
        return MdnsProbe._sendPacket(socket, probe, opts);
    }
    static _sendAnnouncement(socket, opts) {
        const reply = new Packet();
        reply.header.id = 0;
        reply.header.qr = 1;
        reply.header.aa = 1;
        reply.header.rd = 0;
        reply.answers = opts.records.map((r) => {
            const copy = new PacketResource(r.name, r.packetType, r.class | MDNS_CACHE_FLUSH_BIT, r.ttl);
            return copy;
        });
        return MdnsProbe._sendPacket(socket, reply, opts);
    }
    static _sendPacket(socket, packet, opts) {
        return new Promise((resolve, reject) => {
            socket.send(packet.toBuffer(), opts.port, opts.multicastAddr, (err) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve();
                }
            });
        });
    }
    static _nameEquals(a, b) {
        return MdnsProbe._normalizeName(a) === MdnsProbe._normalizeName(b);
    }
    static _normalizeName(s) {
        const lower = s.toLowerCase();
        if (lower.endsWith('.')) {
            return lower.slice(0, -1);
        }
        return lower;
    }
    static _keyInSet(needle, set) {
        for (const k of set) {
            if (Buffer.compare(needle, k) === 0) {
                return true;
            }
        }
        return false;
    }
    static _isMulticast(addr) {
        if (addr.includes(':')) {
            return addr.toLowerCase().startsWith('ff');
        }
        const firstOctet = Number.parseInt(addr.split('.')[0], 10);
        return firstOctet >= 224 && firstOctet <= 239;
    }
}
//# sourceMappingURL=MdnsProbe.js.map