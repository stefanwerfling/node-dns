import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { CAA } from '../Packet/Types/CAA.js';
import { CNAME } from '../Packet/Types/CNAME.js';
import { MX } from '../Packet/Types/MX.js';
import { NS } from '../Packet/Types/NS.js';
import { PTR } from '../Packet/Types/PTR.js';
import { SOA } from '../Packet/Types/SOA.js';
import { SRV } from '../Packet/Types/SRV.js';
import { TXT } from '../Packet/Types/TXT.js';
export class ZoneParser {
    static parse(input, options = {}) {
        const lines = ZoneParser._tokenize(input);
        let origin = ZoneParser._absolute(options.origin ?? '.');
        let defaultTtl = options.defaultTtl ?? 3600;
        let lastName = null;
        let lastTtl = null;
        let lastClass = PacketClass.IN;
        const records = [];
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
        return { origin: origin, records: records };
    }
    static _tokenize(input) {
        const result = [];
        let tokens = [];
        let current = '';
        let inQuote = false;
        let parenDepth = 0;
        let lineNumber = 1;
        let logicalLineStart = 1;
        let leadingWhitespace = false;
        let sawAnyChar = false;
        const flushToken = (quoted) => {
            if (current.length > 0 || quoted) {
                tokens.push({ value: current, quoted: quoted });
                current = '';
            }
        };
        const flushLine = () => {
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
            if (c === ';') {
                while (i < input.length && input[i] !== '\n') {
                    i++;
                }
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
    static _parseRecord(line, ctx) {
        const tokens = line.tokens;
        let i = 0;
        let name;
        if (line.leadingWhitespace) {
            if (ctx.lastName === null) {
                throw new Error(`line ${line.lineNumber}: name required (no previous record to inherit from)`);
            }
            name = ctx.lastName;
        }
        else {
            name = ZoneParser._qualifyName(tokens[0].value, ctx.origin);
            i = 1;
        }
        let ttl = null;
        let cls = null;
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
                    cls = PacketClass[upper];
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
    static _qualifyName(raw, origin) {
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
    static _absolute(name) {
        return name.endsWith('.') ? name : `${name}.`;
    }
    static _stripFinalDot(name) {
        if (name === '.') {
            return '';
        }
        return name.endsWith('.') ? name.slice(0, -1) : name;
    }
    static _parseTtl(raw) {
        if (!/^\d+$/.test(raw)) {
            throw new Error(`invalid TTL value: ${raw}`);
        }
        return parseInt(raw, 10);
    }
    static _parseRdata(typeStr, rdata, origin, lineNumber) {
        const v = (n) => rdata[n].value;
        const fqdn = (raw) => ZoneParser._qualifyName(raw, origin);
        switch (typeStr) {
            case 'A':
                return new A(v(0));
            case 'AAAA':
                return new AAAA(v(0));
            case 'NS':
                return new NS(fqdn(v(0)));
            case 'CNAME':
                return new CNAME(fqdn(v(0)));
            case 'PTR':
                return new PTR(fqdn(v(0)));
            case 'MX':
                return new MX(fqdn(v(1)), parseInt(v(0), 10));
            case 'TXT': {
                const parts = rdata.map((t) => t.value);
                return new TXT(parts.length === 1 ? parts[0] : parts);
            }
            case 'SOA': {
                if (rdata.length < 7) {
                    throw new Error(`line ${lineNumber}: SOA needs 7 fields`);
                }
                return new SOA(fqdn(v(0)), fqdn(v(1)), parseInt(v(2), 10), ZoneParser._parseTtl(v(3)), ZoneParser._parseTtl(v(4)), ZoneParser._parseTtl(v(5)), ZoneParser._parseTtl(v(6)));
            }
            case 'SRV': {
                if (rdata.length < 4) {
                    throw new Error(`line ${lineNumber}: SRV needs 4 fields`);
                }
                return new SRV(parseInt(v(0), 10), parseInt(v(1), 10), parseInt(v(2), 10), fqdn(v(3)));
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
//# sourceMappingURL=ZoneParser.js.map