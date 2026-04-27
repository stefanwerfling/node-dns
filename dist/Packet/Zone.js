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
}
//# sourceMappingURL=Zone.js.map