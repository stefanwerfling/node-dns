import { PacketClass } from '../Packet/PacketClass.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { PTR } from '../Packet/Types/PTR.js';
import { SRV } from '../Packet/Types/SRV.js';
import { TXT } from '../Packet/Types/TXT.js';
import { MdnsClient } from './MdnsClient.js';
export class ServiceDiscovery {
    static async browse(options) {
        const domain = options.domain ?? 'local';
        const queryName = `${options.serviceType}.${domain}`;
        const resolveMissing = options.resolveMissing ?? true;
        const mdnsOpts = {
            ...(options.mdns ?? {}),
            timeoutMs: options.timeoutMs ?? options.mdns?.timeoutMs ?? 1000
        };
        const resolve = MdnsClient.request(mdnsOpts);
        const responses = await resolve(queryName, PacketTypes.PTR);
        const byInstance = new Map();
        const cnames = new Map();
        for (const r of responses) {
            ServiceDiscovery._foldRecords(r.packet.answers, byInstance, cnames);
            ServiceDiscovery._foldRecords(r.additionals, byInstance, cnames);
        }
        for (const inst of byInstance.values()) {
            if (inst.host !== undefined) {
                const addrs = cnames.get(ServiceDiscovery._normalize(inst.host));
                if (addrs !== undefined) {
                    inst.addresses = Array.from(new Set([...inst.addresses, ...addrs]));
                }
            }
        }
        if (!resolveMissing) {
            return Array.from(byInstance.values());
        }
        const sub = MdnsClient.request(mdnsOpts);
        const followUps = [];
        for (const inst of byInstance.values()) {
            if (inst.host === undefined || inst.port === undefined) {
                followUps.push(ServiceDiscovery._fillSrv(sub, inst));
            }
            if (inst.txt === undefined) {
                followUps.push(ServiceDiscovery._fillTxt(sub, inst));
            }
        }
        await Promise.all(followUps);
        const addrFollowUps = [];
        for (const inst of byInstance.values()) {
            if (inst.host !== undefined && inst.addresses.length === 0) {
                addrFollowUps.push(ServiceDiscovery._fillAddresses(sub, inst));
            }
        }
        await Promise.all(addrFollowUps);
        return Array.from(byInstance.values());
    }
    static async resolveInstance(instanceName, options = {}) {
        const mdnsOpts = {
            ...(options.mdns ?? {}),
            timeoutMs: options.timeoutMs ?? options.mdns?.timeoutMs ?? 1000
        };
        const inst = { name: instanceName, addresses: [] };
        const sub = MdnsClient.request(mdnsOpts);
        await Promise.all([
            ServiceDiscovery._fillSrv(sub, inst),
            ServiceDiscovery._fillTxt(sub, inst)
        ]);
        if (inst.host !== undefined && inst.addresses.length === 0) {
            await ServiceDiscovery._fillAddresses(sub, inst);
        }
        return inst;
    }
    static _foldRecords(records, byInstance, cnames) {
        for (const rec of records) {
            const t = rec.packetType;
            if (t instanceof PTR) {
                const key = ServiceDiscovery._normalize(t.domain);
                if (!byInstance.has(key)) {
                    byInstance.set(key, { name: t.domain, addresses: [] });
                }
            }
            else if (t instanceof SRV) {
                const key = ServiceDiscovery._normalize(rec.name);
                const inst = byInstance.get(key) ?? { name: rec.name, addresses: [] };
                inst.host = t.target;
                inst.port = t.port;
                inst.priority = t.priority;
                inst.weight = t.weight;
                byInstance.set(key, inst);
            }
            else if (t instanceof TXT) {
                const key = ServiceDiscovery._normalize(rec.name);
                const inst = byInstance.get(key) ?? { name: rec.name, addresses: [] };
                inst.txt = ServiceDiscovery._parseTxt(t);
                byInstance.set(key, inst);
            }
            else if (t instanceof A || t instanceof AAAA) {
                const host = ServiceDiscovery._normalize(rec.name);
                const addr = t.address;
                const list = cnames.get(host) ?? [];
                if (!list.includes(addr)) {
                    list.push(addr);
                }
                cnames.set(host, list);
            }
        }
    }
    static async _fillSrv(resolve, inst) {
        const responses = await resolve(inst.name, PacketTypes.SRV);
        for (const r of responses) {
            for (const rec of r.packet.answers) {
                if (rec.packetType instanceof SRV
                    && ServiceDiscovery._normalize(rec.name) === ServiceDiscovery._normalize(inst.name)) {
                    inst.host = rec.packetType.target;
                    inst.port = rec.packetType.port;
                    inst.priority = rec.packetType.priority;
                    inst.weight = rec.packetType.weight;
                    return;
                }
            }
        }
    }
    static async _fillTxt(resolve, inst) {
        const responses = await resolve(inst.name, PacketTypes.TXT);
        for (const r of responses) {
            for (const rec of r.packet.answers) {
                if (rec.packetType instanceof TXT
                    && ServiceDiscovery._normalize(rec.name) === ServiceDiscovery._normalize(inst.name)) {
                    inst.txt = ServiceDiscovery._parseTxt(rec.packetType);
                    return;
                }
            }
        }
    }
    static async _fillAddresses(resolve, inst) {
        if (inst.host === undefined) {
            return;
        }
        const target = inst.host;
        const merge = (rec) => {
            if ((rec.packetType instanceof A || rec.packetType instanceof AAAA)
                && ServiceDiscovery._normalize(rec.name) === ServiceDiscovery._normalize(target)) {
                const addr = rec.packetType.address;
                if (!inst.addresses.includes(addr)) {
                    inst.addresses.push(addr);
                }
            }
        };
        const [a, aaaa] = await Promise.all([
            resolve(target, PacketTypes.A, PacketClass.IN),
            resolve(target, PacketTypes.AAAA, PacketClass.IN)
        ]);
        for (const r of [...a, ...aaaa]) {
            for (const rec of r.packet.answers) {
                merge(rec);
            }
            for (const rec of r.additionals) {
                merge(rec);
            }
        }
    }
    static _normalize(name) {
        const stripped = name.endsWith('.') && name.length > 1 ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }
    static _parseTxt(txt) {
        const out = {};
        const data = Array.isArray(txt.data) ? txt.data : [txt.data];
        for (const entry of data) {
            if (entry.length === 0) {
                continue;
            }
            const eq = entry.indexOf('=');
            const key = eq === -1 ? entry : entry.slice(0, eq);
            if (key.length === 0) {
                continue;
            }
            if (out[key] !== undefined) {
                continue;
            }
            out[key] = eq === -1 ? true : entry.slice(eq + 1);
        }
        return out;
    }
}
//# sourceMappingURL=ServiceDiscovery.js.map