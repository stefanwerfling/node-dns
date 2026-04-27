import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketType } from '../Packet/PacketType.js';
export type ZoneToken = {
    value: string;
    quoted: boolean;
};
export type ZoneTokenLine = {
    tokens: ZoneToken[];
    lineNumber: number;
    leadingWhitespace: boolean;
};
export type ZoneParseResult = {
    origin: string;
    records: PacketResource[];
};
export type ZoneParseOptions = {
    origin?: string;
    defaultTtl?: number;
};
export declare class ZoneParser {
    static parse(input: string, options?: ZoneParseOptions): ZoneParseResult;
    protected static _tokenize(input: string): ZoneTokenLine[];
    protected static _parseRecord(line: ZoneTokenLine, ctx: {
        origin: string;
        defaultTtl: number;
        lastName: string | null;
        lastTtl: number | null;
        lastClass: PacketClass;
    }): PacketResource;
    protected static _qualifyName(raw: string, origin: string): string;
    protected static _absolute(name: string): string;
    protected static _stripFinalDot(name: string): string;
    protected static _parseTtl(raw: string): number;
    protected static _parseRdata(typeStr: string, rdata: ZoneToken[], origin: string, lineNumber: number): PacketType;
}
