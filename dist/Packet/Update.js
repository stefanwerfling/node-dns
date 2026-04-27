import { Buffer } from 'buffer';
import { Packet } from './Packet.js';
import { PacketClass } from './PacketClass.js';
import { PacketOpcode } from './PacketOpcode.js';
import { PacketQuestion } from './PacketQuestion.js';
import { PacketResource } from './PacketResource.js';
import { PacketTypes } from './PacketTypes.js';
import { UnknownPacketType } from './Types/UnknownPacketType.js';
export var UpdateRcode;
(function (UpdateRcode) {
    UpdateRcode[UpdateRcode["NOERROR"] = 0] = "NOERROR";
    UpdateRcode[UpdateRcode["FORMERR"] = 1] = "FORMERR";
    UpdateRcode[UpdateRcode["SERVFAIL"] = 2] = "SERVFAIL";
    UpdateRcode[UpdateRcode["NXDOMAIN"] = 3] = "NXDOMAIN";
    UpdateRcode[UpdateRcode["NOTIMP"] = 4] = "NOTIMP";
    UpdateRcode[UpdateRcode["REFUSED"] = 5] = "REFUSED";
    UpdateRcode[UpdateRcode["YXDOMAIN"] = 6] = "YXDOMAIN";
    UpdateRcode[UpdateRcode["YXRRSET"] = 7] = "YXRRSET";
    UpdateRcode[UpdateRcode["NXRRSET"] = 8] = "NXRRSET";
    UpdateRcode[UpdateRcode["NOTAUTH"] = 9] = "NOTAUTH";
    UpdateRcode[UpdateRcode["NOTZONE"] = 10] = "NOTZONE";
})(UpdateRcode || (UpdateRcode = {}));
const emptyRdata = (typeCode) => new UnknownPacketType(typeCode, Buffer.alloc(0));
export class UpdateBuilder {
    _zoneName;
    _zoneClass;
    _prerequisites = [];
    _updates = [];
    constructor(zoneName, cls = PacketClass.IN) {
        this._zoneName = UpdateBuilder._stripFinalDot(zoneName);
        this._zoneClass = cls;
    }
    requireNameInUse(name) {
        this._prerequisites.push(new PacketResource(UpdateBuilder._stripFinalDot(name), emptyRdata(PacketTypes.ANY), PacketClass.ANY, 0));
        return this;
    }
    requireNameNotInUse(name) {
        this._prerequisites.push(new PacketResource(UpdateBuilder._stripFinalDot(name), emptyRdata(PacketTypes.ANY), PacketClass.NONE, 0));
        return this;
    }
    requireRRsetExists(name, type) {
        this._prerequisites.push(new PacketResource(UpdateBuilder._stripFinalDot(name), emptyRdata(type), PacketClass.ANY, 0));
        return this;
    }
    requireRRsetAbsent(name, type) {
        this._prerequisites.push(new PacketResource(UpdateBuilder._stripFinalDot(name), emptyRdata(type), PacketClass.NONE, 0));
        return this;
    }
    requireRRsetMatches(record) {
        const cloned = new PacketResource(UpdateBuilder._stripFinalDot(record.name), record.packetType, this._zoneClass, 0);
        this._prerequisites.push(cloned);
        return this;
    }
    add(record) {
        const cloned = new PacketResource(UpdateBuilder._stripFinalDot(record.name), record.packetType, this._zoneClass, record.ttl);
        this._updates.push(cloned);
        return this;
    }
    deleteName(name) {
        this._updates.push(new PacketResource(UpdateBuilder._stripFinalDot(name), emptyRdata(PacketTypes.ANY), PacketClass.ANY, 0));
        return this;
    }
    deleteRRset(name, type) {
        this._updates.push(new PacketResource(UpdateBuilder._stripFinalDot(name), emptyRdata(type), PacketClass.ANY, 0));
        return this;
    }
    deleteRR(record) {
        const cloned = new PacketResource(UpdateBuilder._stripFinalDot(record.name), record.packetType, PacketClass.NONE, 0);
        this._updates.push(cloned);
        return this;
    }
    toPacket() {
        const packet = new Packet();
        packet.header.id = Math.floor(Math.random() * 0x10000);
        packet.header.opcode = PacketOpcode.UPDATE;
        packet.header.rd = 0;
        packet.questions.push(new PacketQuestion(this._zoneName, PacketTypes.SOA, this._zoneClass));
        packet.answers = this._prerequisites.slice();
        packet.authorities = this._updates.slice();
        return packet;
    }
    toBuffer() {
        return this.toPacket().toBuffer();
    }
    static _stripFinalDot(name) {
        if (name === '.') {
            return '';
        }
        return name.endsWith('.') ? name.slice(0, -1) : name;
    }
}
export class Update {
    static parse(packet) {
        if (packet.questions.length !== 1) {
            throw new Error('UPDATE message must have exactly one Zone (question) entry');
        }
        const q = packet.questions[0];
        return {
            zoneName: q.name,
            zoneClass: q.class,
            prerequisites: packet.answers.slice(),
            updates: packet.authorities.slice(),
        };
    }
    static classifyPrerequisite(rr) {
        const isEmpty = Update._isEmptyRdata(rr);
        if (rr.class === PacketClass.ANY) {
            if (rr.packetType.type === PacketTypes.ANY && isEmpty) {
                return { kind: 'nameInUse', name: rr.name };
            }
            if (isEmpty) {
                return { kind: 'rrsetExists', name: rr.name, type: rr.packetType.type };
            }
        }
        if (rr.class === PacketClass.NONE) {
            if (rr.packetType.type === PacketTypes.ANY && isEmpty) {
                return { kind: 'nameNotInUse', name: rr.name };
            }
            if (isEmpty) {
                return { kind: 'rrsetAbsent', name: rr.name, type: rr.packetType.type };
            }
        }
        return { kind: 'rrsetMatchesExactly', name: rr.name, type: rr.packetType.type, record: rr };
    }
    static classifyUpdate(rr) {
        const isEmpty = Update._isEmptyRdata(rr);
        if (rr.class === PacketClass.ANY) {
            if (rr.packetType.type === PacketTypes.ANY && isEmpty) {
                return { kind: 'deleteName', name: rr.name };
            }
            if (isEmpty) {
                return { kind: 'deleteRRset', name: rr.name, type: rr.packetType.type };
            }
        }
        if (rr.class === PacketClass.NONE) {
            return { kind: 'deleteRR', record: rr };
        }
        return { kind: 'add', record: rr };
    }
    static _isEmptyRdata(rr) {
        if (rr.rdlength !== undefined) {
            return rr.rdlength === 0;
        }
        return rr.packetType instanceof UnknownPacketType
            && rr.packetType.data.length === 0;
    }
    static applyToZone(zone, msg) {
        const zoneOrigin = Update._stripFinalDot(zone.origin);
        if (Update._stripFinalDot(msg.zoneName) !== zoneOrigin) {
            return UpdateRcode.NOTZONE;
        }
        for (const pre of msg.prerequisites) {
            const check = Update.classifyPrerequisite(pre);
            const ok = Update._evaluatePrerequisite(zone, check);
            if (!ok.satisfied) {
                return ok.failureRcode;
            }
        }
        for (const upd of msg.updates) {
            const action = Update.classifyUpdate(upd);
            Update._applyAction(zone, action);
        }
        return UpdateRcode.NOERROR;
    }
    static _evaluatePrerequisite(zone, check) {
        const recordsAtName = zone.records.filter((r) => Update._sameName(r.name, check.name));
        switch (check.kind) {
            case 'nameInUse':
                return recordsAtName.length > 0
                    ? { satisfied: true }
                    : { satisfied: false, failureRcode: UpdateRcode.NXDOMAIN };
            case 'nameNotInUse':
                return recordsAtName.length === 0
                    ? { satisfied: true }
                    : { satisfied: false, failureRcode: UpdateRcode.YXDOMAIN };
            case 'rrsetExists':
                return recordsAtName.some((r) => r.packetType.type === check.type)
                    ? { satisfied: true }
                    : { satisfied: false, failureRcode: UpdateRcode.NXRRSET };
            case 'rrsetAbsent':
                return recordsAtName.some((r) => r.packetType.type === check.type)
                    ? { satisfied: false, failureRcode: UpdateRcode.YXRRSET }
                    : { satisfied: true };
            case 'rrsetMatchesExactly': {
                const existing = recordsAtName.filter((r) => r.packetType.type === check.type);
                const provided = [check.record];
                const existingBytes = existing.map(Update._rdataBytes).sort();
                const providedBytes = provided.map(Update._rdataBytes).sort();
                if (existingBytes.length !== providedBytes.length) {
                    return { satisfied: false, failureRcode: UpdateRcode.NXRRSET };
                }
                for (let i = 0; i < existingBytes.length; i++) {
                    if (!existingBytes[i].equals(providedBytes[i])) {
                        return { satisfied: false, failureRcode: UpdateRcode.NXRRSET };
                    }
                }
                return { satisfied: true };
            }
            default:
                return { satisfied: false, failureRcode: UpdateRcode.FORMERR };
        }
    }
    static _applyAction(zone, action) {
        switch (action.kind) {
            case 'deleteName':
                zone.records = zone.records.filter((r) => !Update._sameName(r.name, action.name));
                return;
            case 'deleteRRset':
                zone.records = zone.records.filter((r) => !(Update._sameName(r.name, action.name) && r.packetType.type === action.type));
                return;
            case 'deleteRR': {
                const targetBytes = Update._rdataBytes(action.record);
                zone.records = zone.records.filter((r) => {
                    if (!Update._sameName(r.name, action.record.name)) {
                        return true;
                    }
                    if (r.packetType.type !== action.record.packetType.type) {
                        return true;
                    }
                    return !Update._rdataBytes(r).equals(targetBytes);
                });
                return;
            }
            case 'add':
                {
                    const newBytes = Update._rdataBytes(action.record);
                    const idx = zone.records.findIndex((r) => Update._sameName(r.name, action.record.name) &&
                        r.packetType.type === action.record.packetType.type &&
                        Update._rdataBytes(r).equals(newBytes));
                    if (idx >= 0) {
                        zone.records[idx].ttl = action.record.ttl;
                    }
                    else {
                        zone.records.push(action.record);
                    }
                }
                return;
        }
    }
    static _rdataBytes(rr) {
        const encoded = rr.packetType.encode(rr);
        return encoded.length >= 2 ? encoded.subarray(2) : encoded;
    }
    static _sameName(a, b) {
        return Update._stripFinalDot(a).toLowerCase() === Update._stripFinalDot(b).toLowerCase();
    }
    static _stripFinalDot(name) {
        if (name === '.') {
            return '';
        }
        return name.endsWith('.') ? name.slice(0, -1) : name;
    }
    static buildResponse(request, rcode) {
        const response = Packet.createResponseFromRequest(request);
        response.questions = request.questions.slice();
        response.header.opcode = PacketOpcode.UPDATE;
        response.header.aa = 1;
        response.header.rcode = rcode;
        response.answers = [];
        response.authorities = [];
        return response;
    }
}
//# sourceMappingURL=Update.js.map