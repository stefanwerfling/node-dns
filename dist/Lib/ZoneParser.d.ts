import { Buffer } from 'buffer';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { SVCB, SvcParams } from '../Packet/Types/SVCB.js';
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
export type ZoneIncludeResolver = (filename: string, basePath: string | undefined) => string;
export type ZoneParseOptions = {
    origin?: string;
    defaultTtl?: number;
    basePath?: string;
    includeResolver?: ZoneIncludeResolver;
};
export declare class ZoneParser {
    static parse(input: string, options?: ZoneParseOptions): ZoneParseResult;
    protected static _parseInternal(input: string, options: ZoneParseOptions, visitedFiles: Set<string>): ZoneParseResult;
    protected static _resolveIncludePath(filename: string, basePath: string | undefined): string;
    protected static _loadInclude(filename: string, options: ZoneParseOptions, resolvedPath: string, lineNumber: number): string;
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
    protected static _typeMnemonicToNumber(mnemonic: string, lineNumber: number): number;
    protected static _base32hexDecode(input: string): Buffer;
    protected static _parseRdata(typeStr: string, rdata: ZoneToken[], origin: string, lineNumber: number): PacketType;
    protected static _parseSvcb(rdata: ZoneToken[], origin: string, lineNumber: number, isHttps: boolean): SVCB;
    protected static _applySvcParam(params: SvcParams, key: string, value: string | null, lineNumber: number): void;
    protected static _splitList(value: string | null, key: string, lineNumber: number): string[];
    protected static _svcParamKeyToNumber(name: string, lineNumber: number): number;
}
