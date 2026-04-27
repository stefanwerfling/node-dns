import { Buffer } from 'buffer';
import { Packet } from './Packet.js';
import { PacketClass } from './PacketClass.js';
import { PacketResource } from './PacketResource.js';
import { PacketTypes } from './PacketTypes.js';
import { Zone } from './Zone.js';
export declare enum UpdateRcode {
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
export type UpdateAction = {
    kind: 'add';
    record: PacketResource;
} | {
    kind: 'deleteName';
    name: string;
} | {
    kind: 'deleteRRset';
    name: string;
    type: PacketTypes | number;
} | {
    kind: 'deleteRR';
    record: PacketResource;
};
export type PrerequisiteCheck = {
    kind: 'nameInUse';
    name: string;
} | {
    kind: 'nameNotInUse';
    name: string;
} | {
    kind: 'rrsetExists';
    name: string;
    type: PacketTypes | number;
} | {
    kind: 'rrsetAbsent';
    name: string;
    type: PacketTypes | number;
} | {
    kind: 'rrsetMatchesExactly';
    name: string;
    type: PacketTypes | number;
    record: PacketResource;
};
export type ParsedUpdate = {
    zoneName: string;
    zoneClass: PacketClass | number;
    prerequisites: PacketResource[];
    updates: PacketResource[];
};
export declare class UpdateBuilder {
    protected _zoneName: string;
    protected _zoneClass: PacketClass;
    protected _prerequisites: PacketResource[];
    protected _updates: PacketResource[];
    constructor(zoneName: string, cls?: PacketClass);
    requireNameInUse(name: string): this;
    requireNameNotInUse(name: string): this;
    requireRRsetExists(name: string, type: PacketTypes | number): this;
    requireRRsetAbsent(name: string, type: PacketTypes | number): this;
    requireRRsetMatches(record: PacketResource): this;
    add(record: PacketResource): this;
    deleteName(name: string): this;
    deleteRRset(name: string, type: PacketTypes | number): this;
    deleteRR(record: PacketResource): this;
    toPacket(): Packet;
    toBuffer(): Buffer;
    protected static _stripFinalDot(name: string): string;
}
export declare class Update {
    static parse(packet: Packet): ParsedUpdate;
    static classifyPrerequisite(rr: PacketResource): PrerequisiteCheck;
    static classifyUpdate(rr: PacketResource): UpdateAction;
    protected static _isEmptyRdata(rr: PacketResource): boolean;
    static applyToZone(zone: Zone, msg: ParsedUpdate): UpdateRcode;
    protected static _evaluatePrerequisite(zone: Zone, check: PrerequisiteCheck): {
        satisfied: true;
    } | {
        satisfied: false;
        failureRcode: UpdateRcode;
    };
    protected static _applyAction(zone: Zone, action: UpdateAction): void;
    protected static _rdataBytes(rr: PacketResource): Buffer;
    protected static _sameName(a: string, b: string): boolean;
    protected static _stripFinalDot(name: string): string;
    static buildResponse(request: Packet, rcode: UpdateRcode): Packet;
}
