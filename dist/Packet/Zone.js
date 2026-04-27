import { ZoneParser } from '../Lib/ZoneParser.js';
import { Packet } from './Packet.js';
import { PacketTypes } from './PacketTypes.js';
export class Zone {
    origin;
    records;
    constructor(origin, records = []) {
        this.origin = origin.endsWith('.') ? origin : `${origin}.`;
        this.records = records;
    }
    static fromZoneFile(text, options = {}) {
        const parsed = ZoneParser.parse(text, options);
        return new Zone(parsed.origin, parsed.records);
    }
    soa() {
        const soa = this.records.find((r) => r.packetType.type === PacketTypes.SOA);
        if (!soa) {
            throw new Error('zone has no SOA record');
        }
        return soa;
    }
    *recordsOfType(type) {
        for (const r of this.records) {
            if (r.packetType.type === type) {
                yield r;
            }
        }
    }
    toAxfrPackets(query) {
        const soa = this.soa();
        const response = Packet.createResponseFromRequest(query);
        response.questions = query.questions.slice();
        response.header.aa = 1;
        response.answers = [soa, ...this.records.filter((r) => r !== soa), soa];
        return [response];
    }
    soaRdata() {
        return this.soa().packetType;
    }
    toIxfrPackets(query, options = {}) {
        const currentSoa = this.soa();
        const currentSerial = currentSoa.packetType.serial;
        const clientSerial = Zone._extractClientSerial(query);
        const response = Packet.createResponseFromRequest(query);
        response.questions = query.questions.slice();
        response.header.aa = 1;
        if (clientSerial === null) {
            return this.toAxfrPackets(query);
        }
        if (clientSerial === currentSerial) {
            response.answers = [currentSoa];
            return [response];
        }
        const chain = Zone._stitchChain(options.history ?? [], clientSerial, currentSerial);
        if (chain === null) {
            return this.toAxfrPackets(query);
        }
        const answers = [currentSoa];
        for (const cs of chain) {
            answers.push(cs.fromSoa, ...cs.deletions);
            answers.push(cs.toSoa, ...cs.additions);
        }
        answers.push(currentSoa);
        response.answers = answers;
        return [response];
    }
    static _extractClientSerial(query) {
        for (const r of query.authorities) {
            if (r.packetType.type === PacketTypes.SOA) {
                return r.packetType.serial;
            }
        }
        return null;
    }
    static _stitchChain(history, from, to) {
        const chain = [];
        let cursor = from;
        while (cursor !== to) {
            const next = history.find((h) => h.fromSerial === cursor);
            if (!next) {
                return null;
            }
            chain.push(next);
            cursor = next.toSerial;
        }
        return chain;
    }
}
//# sourceMappingURL=Zone.js.map