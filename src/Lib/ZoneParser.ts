import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {CAA} from '../Packet/Types/CAA.js';
import {CNAME} from '../Packet/Types/CNAME.js';
import {DNAME} from '../Packet/Types/DNAME.js';
import {MX} from '../Packet/Types/MX.js';
import {NS} from '../Packet/Types/NS.js';
import {PTR} from '../Packet/Types/PTR.js';
import {SOA} from '../Packet/Types/SOA.js';
import {SRV} from '../Packet/Types/SRV.js';
import {TXT} from '../Packet/Types/TXT.js';
import {PacketType} from '../Packet/PacketType.js';

/**
 * Single token produced by the tokenizer. `quoted` records whether the
 * value originated from a `"..."` literal — TXT records care, MX numbers do not.
 */
export type ZoneToken = {
    value: string;
    quoted: boolean;
};

/**
 * One logical line from the master file. Multi-line records joined with
 * parens become a single logical line. `leadingWhitespace` tracks whether
 * the line started with whitespace — RFC 1035 §5.1 uses this to distinguish
 * "this line declares a new owner name" from "this line inherits the
 * previous owner name".
 */
export type ZoneTokenLine = {
    tokens: ZoneToken[];
    lineNumber: number;
    leadingWhitespace: boolean;
};

/**
 * Result of parsing a zone file.
 */
export type ZoneParseResult = {
    origin: string;
    records: PacketResource[];
};

/**
 * Options for `ZoneParser.parse`.
 */
export type ZoneParseOptions = {
    /**
     * Origin to use when no `$ORIGIN` directive is present and a name is
     * relative or `@`. Trailing dot is added automatically if missing.
     */
    origin?: string;

    /**
     * Default TTL for records that omit one. Used until/unless a `$TTL`
     * directive sets a new default. Defaults to 3600.
     */
    defaultTtl?: number;
};

/**
 * Parser for the RFC 1035 master file format ("zone file").
 *
 * Supports:
 *   - `;` comments, `( … )` multi-line records, `"…"` quoted strings
 *     with `\\` and `\"` escapes
 *   - `$ORIGIN`, `$TTL` directives
 *   - `@` shortcut for the current origin
 *   - TTL/class inheritance from the previous record
 *   - RDATA for A, AAAA, NS, CNAME, DNAME, PTR, MX, TXT, SOA, SRV, CAA
 *
 * Not yet supported (intentional): `$INCLUDE` (filesystem I/O),
 * generic-encoding `\#`, DNSSEC RDATA types (DNSKEY/DS/RRSIG/…).
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc1035#section-5
 */
export class ZoneParser {

    public static parse(input: string, options: ZoneParseOptions = {}): ZoneParseResult {
        const lines = ZoneParser._tokenize(input);
        let origin = ZoneParser._absolute(options.origin ?? '.');
        let defaultTtl = options.defaultTtl ?? 3600;

        let lastName: string|null = null;
        let lastTtl: number|null = null;
        let lastClass: PacketClass = PacketClass.IN;
        const records: PacketResource[] = [];

        for (const line of lines) {
            if (line.tokens.length === 0) {
                continue;
            }

            const first = line.tokens[0].value;

            if (first === '$ORIGIN') {
                if (line.tokens.length < 2) {
                    throw new Error(`line ${line.lineNumber}: $ORIGIN requires a domain`);
                }

                origin = ZoneParser._absolute(line.tokens[1].value);
                continue;
            }

            if (first === '$TTL') {
                if (line.tokens.length < 2) {
                    throw new Error(`line ${line.lineNumber}: $TTL requires a value`);
                }

                defaultTtl = ZoneParser._parseTtl(line.tokens[1].value);
                continue;
            }

            if (first.startsWith('$')) {
                throw new Error(`line ${line.lineNumber}: unsupported directive ${first}`);
            }

            const record = ZoneParser._parseRecord(line, {
                origin: origin,
                defaultTtl: defaultTtl,
                lastName: lastName,
                lastTtl: lastTtl,
                lastClass: lastClass,
            });

            lastName = record.name;
            lastTtl = record.ttl;
            lastClass = record.class;
            records.push(record);
        }

        return {origin: origin, records: records};
    }

    /**
     * Lexer: turn raw zone text into an array of logical lines. Multi-line
     * records joined with parens collapse to a single logical line. Comments
     * are stripped (but not inside quoted strings). Quotes are preserved as
     * single tokens with `quoted: true`.
     * @param {string} input
     * @return {ZoneTokenLine[]}
     * @protected
     */
    protected static _tokenize(input: string): ZoneTokenLine[] {
        const result: ZoneTokenLine[] = [];
        let tokens: ZoneToken[] = [];
        let current = '';
        let inQuote = false;
        let parenDepth = 0;
        let lineNumber = 1;
        let logicalLineStart = 1;
        let leadingWhitespace = false;
        let sawAnyChar = false;

        const flushToken = (quoted: boolean): void => {
            if (current.length > 0 || quoted) {
                tokens.push({value: current, quoted: quoted});
                current = '';
            }
        };

        const flushLine = (): void => {
            flushToken(false);

            if (tokens.length > 0) {
                result.push({
                    tokens: tokens,
                    lineNumber: logicalLineStart,
                    leadingWhitespace: leadingWhitespace,
                });
            }

            tokens = [];
            logicalLineStart = lineNumber + 1;
            leadingWhitespace = false;
            sawAnyChar = false;
        };

        for (let i = 0; i < input.length; i++) {
            const c = input[i];

            if (inQuote) {
                if (c === '\\' && i + 1 < input.length) {
                    const n = input[i + 1];

                    if (n === '"' || n === '\\') {
                        current += n;
                        i++;
                        continue;
                    }
                }

                if (c === '"') {
                    flushToken(true);
                    inQuote = false;
                    continue;
                }

                if (c === '\n') {
                    lineNumber++;
                }

                current += c;
                continue;
            }

            // Outside quotes
            if (c === ';') {
                // Skip to end of line
                while (i < input.length && input[i] !== '\n') {
                    i++;
                }

                // Position now at '\n' or end. Re-enter loop to handle the newline.
                i--;
                continue;
            }

            if (c === '"') {
                flushToken(false);
                inQuote = true;
                continue;
            }

            if (c === '(') {
                flushToken(false);
                parenDepth++;
                continue;
            }

            if (c === ')') {
                flushToken(false);

                if (parenDepth === 0) {
                    throw new Error(`unmatched ')' at line ${lineNumber}`);
                }

                parenDepth--;
                continue;
            }

            if (c === '\n') {
                flushToken(false);
                lineNumber++;

                if (parenDepth === 0) {
                    flushLine();
                    logicalLineStart = lineNumber;
                }

                continue;
            }

            if (c === ' ' || c === '\t' || c === '\r') {
                if (!sawAnyChar) {
                    leadingWhitespace = true;
                }

                flushToken(false);
                continue;
            }

            sawAnyChar = true;
            current += c;
        }

        if (inQuote) {
            throw new Error(`unterminated quoted string starting near line ${logicalLineStart}`);
        }

        if (parenDepth !== 0) {
            throw new Error(`unmatched '(' starting near line ${logicalLineStart}`);
        }

        flushLine();
        return result;
    }

    /**
     * Parse one tokenized record line into a PacketResource.
     * @protected
     */
    protected static _parseRecord(
        line: ZoneTokenLine,
        ctx: {origin: string; defaultTtl: number; lastName: string|null; lastTtl: number|null; lastClass: PacketClass;}
    ): PacketResource {
        const tokens = line.tokens;
        let i = 0;
        let name: string;

        // RFC 1035 §5.1: a leading-whitespace line inherits the previous
        // owner name; otherwise the first token IS the owner name.
        if (line.leadingWhitespace) {
            if (ctx.lastName === null) {
                throw new Error(`line ${line.lineNumber}: name required (no previous record to inherit from)`);
            }

            name = ctx.lastName;
        } else {
            name = ZoneParser._qualifyName(tokens[0].value, ctx.origin);
            i = 1;
        }

        // Optional TTL + class in any order
        let ttl: number|null = null;
        let cls: PacketClass|null = null;

        for (let pass = 0; pass < 2 && i < tokens.length; pass++) {
            const tok = tokens[i].value;

            if (ttl === null && /^\d+$/.test(tok)) {
                ttl = parseInt(tok, 10);
                i++;
                continue;
            }

            if (cls === null) {
                const upper = tok.toUpperCase();

                if (upper === 'IN' || upper === 'CH' || upper === 'HS' || upper === 'ANY') {
                    cls = PacketClass[upper as keyof typeof PacketClass];
                    i++;
                    continue;
                }
            }

            break;
        }

        if (ttl === null) {
            ttl = ctx.lastTtl ?? ctx.defaultTtl;
        }

        if (cls === null) {
            cls = ctx.lastClass;
        }

        if (i >= tokens.length) {
            throw new Error(`line ${line.lineNumber}: missing record type`);
        }

        const typeStr = tokens[i].value.toUpperCase();
        i++;

        const rdata = tokens.slice(i);
        const packetType = ZoneParser._parseRdata(typeStr, rdata, ctx.origin, line.lineNumber);

        return new PacketResource(name, packetType, cls, ttl);
    }

    /**
     * Resolve `@`, relative, or absolute name against the current origin.
     * @protected
     */
    protected static _qualifyName(raw: string, origin: string): string {
        if (raw === '@') {
            return ZoneParser._stripFinalDot(origin);
        }

        if (raw.endsWith('.')) {
            return ZoneParser._stripFinalDot(raw);
        }

        const baseOrigin = ZoneParser._stripFinalDot(origin);

        if (baseOrigin === '') {
            return raw;
        }

        return `${raw}.${baseOrigin}`;
    }

    protected static _absolute(name: string): string {
        return name.endsWith('.') ? name : `${name}.`;
    }

    protected static _stripFinalDot(name: string): string {
        if (name === '.') {
            return '';
        }

        return name.endsWith('.') ? name.slice(0, -1) : name;
    }

    /**
     * Parse a TTL value. Accepts plain seconds for now; BIND-style suffixes
     * (1h, 2d, 1w) can be added later.
     * @protected
     */
    protected static _parseTtl(raw: string): number {
        if (!/^\d+$/.test(raw)) {
            throw new Error(`invalid TTL value: ${raw}`);
        }

        return parseInt(raw, 10);
    }

    /**
     * Dispatch to per-type RDATA parsers. Throws on unsupported types so the
     * caller knows to extend the parser rather than silently dropping data.
     * @protected
     */
    protected static _parseRdata(typeStr: string, rdata: ZoneToken[], origin: string, lineNumber: number): PacketType {
        const v = (n: number): string => rdata[n].value;
        const fqdn = (raw: string): string => ZoneParser._qualifyName(raw, origin);

        switch (typeStr) {
            case 'A':
                return new A(v(0));

            case 'AAAA':
                return new AAAA(v(0));

            case 'NS':
                return new NS(fqdn(v(0)));

            case 'CNAME':
                return new CNAME(fqdn(v(0)));

            case 'DNAME':
                return new DNAME(fqdn(v(0)));

            case 'PTR':
                return new PTR(fqdn(v(0)));

            case 'MX':
                return new MX(fqdn(v(1)), parseInt(v(0), 10));

            case 'TXT': {
                // Concatenate all character-strings (each token is one).
                const parts = rdata.map((t) => t.value);
                return new TXT(parts.length === 1 ? parts[0] : parts);
            }

            case 'SOA': {
                if (rdata.length < 7) {
                    throw new Error(`line ${lineNumber}: SOA needs 7 fields`);
                }

                return new SOA(
                    fqdn(v(0)),
                    fqdn(v(1)),
                    parseInt(v(2), 10),
                    ZoneParser._parseTtl(v(3)),
                    ZoneParser._parseTtl(v(4)),
                    ZoneParser._parseTtl(v(5)),
                    ZoneParser._parseTtl(v(6))
                );
            }

            case 'SRV': {
                if (rdata.length < 4) {
                    throw new Error(`line ${lineNumber}: SRV needs 4 fields`);
                }

                return new SRV(
                    parseInt(v(0), 10),
                    parseInt(v(1), 10),
                    parseInt(v(2), 10),
                    fqdn(v(3))
                );
            }

            case 'CAA': {
                if (rdata.length < 3) {
                    throw new Error(`line ${lineNumber}: CAA needs 3 fields (flag tag value)`);
                }

                const flag = parseInt(v(0), 10);
                const tag = v(1);
                const value = rdata[2].quoted ? rdata[2].value : rdata.slice(2).map((t) => t.value).join(' ');
                return new CAA(flag, tag, value);
            }

            default:
                throw new Error(`line ${lineNumber}: unsupported record type ${typeStr}`);
        }
    }

}