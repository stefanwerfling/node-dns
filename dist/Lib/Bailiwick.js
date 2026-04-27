import { Packet } from '../Packet/Packet.js';
export class Bailiwick {
    static contains(zone, name) {
        const z = Bailiwick._normalize(zone);
        const n = Bailiwick._normalize(name);
        if (z === '') {
            return true;
        }
        if (n === z) {
            return true;
        }
        return n.endsWith(`.${z}`);
    }
    static filter(packet, zone) {
        const filtered = new Packet();
        filtered.header = packet.header;
        filtered.questions = packet.questions.slice();
        filtered.answers = Bailiwick._inZone(packet.answers, zone);
        filtered.authorities = Bailiwick._inZone(packet.authorities, zone);
        filtered.additionals = Bailiwick._inZone(packet.additionals, zone);
        return filtered;
    }
    static _inZone(records, zone) {
        return records.filter((r) => {
            if (r.name === '') {
                return true;
            }
            return Bailiwick.contains(zone, r.name);
        });
    }
    static _normalize(name) {
        if (name === '.') {
            return '';
        }
        const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }
}
//# sourceMappingURL=Bailiwick.js.map