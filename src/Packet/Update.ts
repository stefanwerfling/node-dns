import {Buffer} from 'buffer';
import {Packet} from './Packet.js';
import {PacketClass} from './PacketClass.js';
import {PacketOpcode} from './PacketOpcode.js';
import {PacketQuestion} from './PacketQuestion.js';
import {PacketResource} from './PacketResource.js';
import {PacketType} from './PacketType.js';
import {PacketTypes} from './PacketTypes.js';
import {UnknownPacketType} from './Types/UnknownPacketType.js';
import {Zone} from './Zone.js';

/**
 * RCODEs that DNS UPDATE responses use beyond the standard query set
 * (RFC 2136 §2.2). Standard NOERROR/SERVFAIL/NOTIMP also apply.
 */
export enum UpdateRcode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    YXRRSET = 7,
    NXRRSET = 8,
    NOTAUTH = 9,
    NOTZONE = 10
}

/**
 * Discriminated description of an update RR (RFC 2136 §2.5).
 */
export type UpdateAction =
    | {kind: 'add'; record: PacketResource;}
    | {kind: 'deleteName'; name: string;}
    | {kind: 'deleteRRset'; name: string; type: PacketTypes|number;}
    | {kind: 'deleteRR'; record: PacketResource;};

/**
 * Discriminated description of a prerequisite RR (RFC 2136 §2.4).
 */
export type PrerequisiteCheck =
    | {kind: 'nameInUse'; name: string;}
    | {kind: 'nameNotInUse'; name: string;}
    | {kind: 'rrsetExists'; name: string; type: PacketTypes|number;}
    | {kind: 'rrsetAbsent'; name: string; type: PacketTypes|number;}
    | {kind: 'rrsetMatchesExactly'; name: string; type: PacketTypes|number; record: PacketResource;};

/**
 * Parsed UPDATE message — the four sections of RFC 2136 §2.3 mapped to
 * named fields.
 */
export type ParsedUpdate = {
    zoneName: string;
    zoneClass: PacketClass|number;
    prerequisites: PacketResource[];
    updates: PacketResource[];
};

/**
 * Empty-RDATA marker used for "delete all" / "name in use" style records.
 * The wire form is just two zero bytes for the rdlength.
 */
const emptyRdata = (typeCode: number): PacketType => new UnknownPacketType(typeCode, Buffer.alloc(0));

/**
 * Builder for DNS UPDATE messages (RFC 2136). The wire format reuses the
 * standard packet sections with new semantics:
 *
 *   - QUESTION  → "Zone" section, exactly one record `(zone, SOA, IN)`
 *   - ANSWER    → "Prerequisite" section
 *   - AUTHORITY → "Update" section
 *   - ADDITIONAL → unchanged (TSIG/EDNS)
 *
 * The opcode is `UPDATE (5)`. Construct one builder, chain the
 * prerequisite/update calls, then call `toPacket()` or `toBuffer()`.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc2136
 */
export class UpdateBuilder {

    /**
     * Zone the update applies to. Stored as the canonical FQDN with no
     * trailing dot — matches the convention `PacketQuestion.name` uses.
     */
    protected _zoneName: string;

    /**
     * Class for the zone — almost always `IN`. Add records inherit this
     * unless overridden.
     */
    protected _zoneClass: PacketClass;

    protected _prerequisites: PacketResource[] = [];
    protected _updates: PacketResource[] = [];

    public constructor(zoneName: string, cls: PacketClass = PacketClass.IN) {
        this._zoneName = UpdateBuilder._stripFinalDot(zoneName);
        this._zoneClass = cls;
    }

    // -- Prerequisites (RFC 2136 §2.4) ----------------------------------

    /**
     * Require that `name` has at least one RR of any type in the zone.
     */
    public requireNameInUse(name: string): this {
        this._prerequisites.push(new PacketResource(
            UpdateBuilder._stripFinalDot(name),
            emptyRdata(PacketTypes.ANY),
            PacketClass.ANY,
            0,
        ));
        return this;
    }

    /**
     * Require that `name` is not present in the zone (no RRs of any type).
     */
    public requireNameNotInUse(name: string): this {
        this._prerequisites.push(new PacketResource(
            UpdateBuilder._stripFinalDot(name),
            emptyRdata(PacketTypes.ANY),
            PacketClass.NONE,
            0,
        ));
        return this;
    }

    /**
     * Require that an RRset of `type` exists at `name`.
     */
    public requireRRsetExists(name: string, type: PacketTypes|number): this {
        this._prerequisites.push(new PacketResource(
            UpdateBuilder._stripFinalDot(name),
            emptyRdata(type),
            PacketClass.ANY,
            0,
        ));
        return this;
    }

    /**
     * Require that no RRset of `type` exists at `name`.
     */
    public requireRRsetAbsent(name: string, type: PacketTypes|number): this {
        this._prerequisites.push(new PacketResource(
            UpdateBuilder._stripFinalDot(name),
            emptyRdata(type),
            PacketClass.NONE,
            0,
        ));
        return this;
    }

    /**
     * Require that the RRset at `(name, record.type)` matches the supplied
     * record exactly (RFC 2136 §2.4.2 "Value Independent" prerequisite).
     */
    public requireRRsetMatches(record: PacketResource): this {
        const cloned = new PacketResource(
            UpdateBuilder._stripFinalDot(record.name),
            record.packetType,
            this._zoneClass,
            0,
        );
        this._prerequisites.push(cloned);
        return this;
    }

    // -- Updates (RFC 2136 §2.5) ----------------------------------------

    /**
     * Add the RR to the zone. TTL on the supplied record is preserved.
     */
    public add(record: PacketResource): this {
        const cloned = new PacketResource(
            UpdateBuilder._stripFinalDot(record.name),
            record.packetType,
            this._zoneClass,
            record.ttl,
        );
        this._updates.push(cloned);
        return this;
    }

    /**
     * Delete every record at `name`, regardless of type.
     */
    public deleteName(name: string): this {
        this._updates.push(new PacketResource(
            UpdateBuilder._stripFinalDot(name),
            emptyRdata(PacketTypes.ANY),
            PacketClass.ANY,
            0,
        ));
        return this;
    }

    /**
     * Delete the entire RRset at `(name, type)`.
     */
    public deleteRRset(name: string, type: PacketTypes|number): this {
        this._updates.push(new PacketResource(
            UpdateBuilder._stripFinalDot(name),
            emptyRdata(type),
            PacketClass.ANY,
            0,
        ));
        return this;
    }

    /**
     * Delete one specific RR from the zone (matched by name, type, RDATA).
     */
    public deleteRR(record: PacketResource): this {
        const cloned = new PacketResource(
            UpdateBuilder._stripFinalDot(record.name),
            record.packetType,
            PacketClass.NONE,
            0,
        );
        this._updates.push(cloned);
        return this;
    }

    // -- Output ---------------------------------------------------------

    public toPacket(): Packet {
        const packet = new Packet();
        packet.header.id = Math.floor(Math.random() * 0x10000);
        packet.header.opcode = PacketOpcode.UPDATE;
        packet.header.rd = 0;
        packet.questions.push(new PacketQuestion(this._zoneName, PacketTypes.SOA, this._zoneClass));
        packet.answers = this._prerequisites.slice();
        packet.authorities = this._updates.slice();
        return packet;
    }

    public toBuffer(): Buffer {
        return this.toPacket().toBuffer();
    }

    protected static _stripFinalDot(name: string): string {
        if (name === '.') {
            return '';
        }

        return name.endsWith('.') ? name.slice(0, -1) : name;
    }

}

/**
 * Helpers for the server side of DNS UPDATE: parsing the four sections,
 * classifying each prerequisite and update record, and a reference
 * implementation of "evaluate prerequisites and apply updates against a
 * Zone" that returns either the new record array or the matching RCODE.
 */
export class Update {

    /**
     * Pull the four UPDATE sections out of a parsed packet. The packet
     * must have been received with `opcode === PacketOpcode.UPDATE`; this
     * method does not verify that.
     */
    public static parse(packet: Packet): ParsedUpdate {
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

    /**
     * Classify a prerequisite RR per RFC 2136 §2.4. The "empty RDATA"
     * marker uses RFC 2136's encoding of rdlength=0 — for parsed records
     * we read `rr.rdlength`; for in-memory records built by `UpdateBuilder`
     * we recognise the `UnknownPacketType` of zero length the builder emits.
     */
    public static classifyPrerequisite(rr: PacketResource): PrerequisiteCheck {
        const isEmpty = Update._isEmptyRdata(rr);

        if (rr.class === PacketClass.ANY) {
            if (rr.packetType.type === PacketTypes.ANY && isEmpty) {
                return {kind: 'nameInUse', name: rr.name};
            }

            if (isEmpty) {
                return {kind: 'rrsetExists', name: rr.name, type: rr.packetType.type};
            }
        }

        if (rr.class === PacketClass.NONE) {
            if (rr.packetType.type === PacketTypes.ANY && isEmpty) {
                return {kind: 'nameNotInUse', name: rr.name};
            }

            if (isEmpty) {
                return {kind: 'rrsetAbsent', name: rr.name, type: rr.packetType.type};
            }
        }

        return {kind: 'rrsetMatchesExactly', name: rr.name, type: rr.packetType.type, record: rr};
    }

    /**
     * Classify an update RR per RFC 2136 §2.5.
     */
    public static classifyUpdate(rr: PacketResource): UpdateAction {
        const isEmpty = Update._isEmptyRdata(rr);

        if (rr.class === PacketClass.ANY) {
            if (rr.packetType.type === PacketTypes.ANY && isEmpty) {
                return {kind: 'deleteName', name: rr.name};
            }

            if (isEmpty) {
                return {kind: 'deleteRRset', name: rr.name, type: rr.packetType.type};
            }
        }

        if (rr.class === PacketClass.NONE) {
            return {kind: 'deleteRR', record: rr};
        }

        return {kind: 'add', record: rr};
    }

    /**
     * "Empty RDATA" check used by `classify*` to distinguish prerequisite/
     * update *markers* (rdlength=0) from real records.
     *
     * For parsed records, `rr.rdlength` is the authoritative value. For
     * in-memory records built by `UpdateBuilder`, we use the
     * `UnknownPacketType` of zero length the builder emits.
     * @protected
     */
    protected static _isEmptyRdata(rr: PacketResource): boolean {
        if (rr.rdlength !== undefined) {
            return rr.rdlength === 0;
        }

        return rr.packetType instanceof UnknownPacketType
            && (rr.packetType as UnknownPacketType).data.length === 0;
    }

    /**
     * Evaluate prerequisites and (if all pass) apply the updates against
     * a `Zone`. Mutates `zone.records` in place and returns the matching
     * RCODE.
     *
     * Returns `UpdateRcode.NOERROR` on success, `NOTZONE` if the message
     * targets a different zone, `NXRRSET`/`YXRRSET`/`NXDOMAIN`/`YXDOMAIN`
     * when prerequisites fail, or `FORMERR` when a record can't be
     * classified (malformed).
     *
     * Atomicity: prerequisites are evaluated against the original zone
     * state. If any prerequisite fails, no updates are applied.
     */
    public static applyToZone(zone: Zone, msg: ParsedUpdate): UpdateRcode {
        const zoneOrigin = Update._stripFinalDot(zone.origin);

        if (Update._stripFinalDot(msg.zoneName) !== zoneOrigin) {
            return UpdateRcode.NOTZONE;
        }

        // Evaluate prerequisites first.
        for (const pre of msg.prerequisites) {
            const check = Update.classifyPrerequisite(pre);
            const ok = Update._evaluatePrerequisite(zone, check);

            if (!ok.satisfied) {
                return ok.failureRcode;
            }
        }

        // Apply updates in order.
        for (const upd of msg.updates) {
            const action = Update.classifyUpdate(upd);
            Update._applyAction(zone, action);
        }

        return UpdateRcode.NOERROR;
    }

    protected static _evaluatePrerequisite(
        zone: Zone,
        check: PrerequisiteCheck,
    ): {satisfied: true;} | {satisfied: false; failureRcode: UpdateRcode;} {
        const recordsAtName = zone.records.filter((r) => Update._sameName(r.name, check.name));

        switch (check.kind) {
            case 'nameInUse':
                return recordsAtName.length > 0
                    ? {satisfied: true}
                    : {satisfied: false, failureRcode: UpdateRcode.NXDOMAIN};

            case 'nameNotInUse':
                return recordsAtName.length === 0
                    ? {satisfied: true}
                    : {satisfied: false, failureRcode: UpdateRcode.YXDOMAIN};

            case 'rrsetExists':
                return recordsAtName.some((r) => r.packetType.type === check.type)
                    ? {satisfied: true}
                    : {satisfied: false, failureRcode: UpdateRcode.NXRRSET};

            case 'rrsetAbsent':
                return recordsAtName.some((r) => r.packetType.type === check.type)
                    ? {satisfied: false, failureRcode: UpdateRcode.YXRRSET}
                    : {satisfied: true};

            case 'rrsetMatchesExactly': {
                // RFC 2136 §3.2.3: the supplied RRset must match the existing
                // one exactly (set equality on RDATA bytes). We compare on
                // the encoded RDATA so type-specific quirks (case in names,
                // canonical form) don't affect the result.
                const existing = recordsAtName.filter((r) => r.packetType.type === check.type);
                const provided = [check.record];
                const existingBytes = existing.map(Update._rdataBytes).sort();
                const providedBytes = provided.map(Update._rdataBytes).sort();

                if (existingBytes.length !== providedBytes.length) {
                    return {satisfied: false, failureRcode: UpdateRcode.NXRRSET};
                }

                for (let i = 0; i < existingBytes.length; i++) {
                    if (!existingBytes[i].equals(providedBytes[i])) {
                        return {satisfied: false, failureRcode: UpdateRcode.NXRRSET};
                    }
                }

                return {satisfied: true};
            }

            default:
                return {satisfied: false, failureRcode: UpdateRcode.FORMERR};
        }
    }

    protected static _applyAction(zone: Zone, action: UpdateAction): void {
        switch (action.kind) {
            case 'deleteName':
                zone.records = zone.records.filter((r) => !Update._sameName(r.name, action.name));
                return;

            case 'deleteRRset':
                zone.records = zone.records.filter((r) =>
                    !(Update._sameName(r.name, action.name) && r.packetType.type === action.type));
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
                // RFC 2136 §3.4.2.5: if an identical RR already exists, the
                // existing one's TTL is replaced. Otherwise the RR is added.
                {
                    const newBytes = Update._rdataBytes(action.record);
                    const idx = zone.records.findIndex((r) =>
                        Update._sameName(r.name, action.record.name) &&
                        r.packetType.type === action.record.packetType.type &&
                        Update._rdataBytes(r).equals(newBytes));

                    if (idx >= 0) {
                        zone.records[idx].ttl = action.record.ttl;
                    } else {
                        zone.records.push(action.record);
                    }
                }
                return;

            // SOA replacement is implicit when an SOA add lands; RFC 2136
            // §3.6 also says a new SOA must have a serial that supersedes
            // the current one — we leave that policy to the caller.
        }
    }

    protected static _rdataBytes(rr: PacketResource): Buffer {
        // Encode the record and slice off the leading 2-byte rdlength.
        // Names-in-RDATA are not compressed in this isolated encode, so the
        // bytes are directly comparable across different containing packets.
        const encoded = rr.packetType.encode(rr);
        return encoded.length >= 2 ? encoded.subarray(2) : encoded;
    }

    protected static _sameName(a: string, b: string): boolean {
        return Update._stripFinalDot(a).toLowerCase() === Update._stripFinalDot(b).toLowerCase();
    }

    protected static _stripFinalDot(name: string): string {
        if (name === '.') {
            return '';
        }

        return name.endsWith('.') ? name.slice(0, -1) : name;
    }

    /**
     * Convenience for handlers: build the response packet for an UPDATE
     * with the given RCODE. Mirrors the request opcode and AA flag and
     * echoes the zone/question section per RFC 2136 §2.2.
     */
    public static buildResponse(request: Packet, rcode: UpdateRcode): Packet {
        const response = Packet.createResponseFromRequest(request);
        response.questions = request.questions.slice();
        response.header.opcode = PacketOpcode.UPDATE;
        response.header.aa = 1;
        response.header.rcode = rcode;
        // Echo prerequisites and updates as empty per RFC; createResponseFromRequest
        // already cleared the additionals.
        response.answers = [];
        response.authorities = [];
        return response;
    }

}
