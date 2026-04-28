import { Buffer } from 'buffer';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { CAA } from '../Packet/Types/CAA.js';
import { CNAME } from '../Packet/Types/CNAME.js';
import { DNAME } from '../Packet/Types/DNAME.js';
import { DNSKEY } from '../Packet/Types/DNSKEY.js';
import { DS } from '../Packet/Types/DS.js';
import { HTTPS } from '../Packet/Types/HTTPS.js';
import { MX } from '../Packet/Types/MX.js';
import { NAPTR } from '../Packet/Types/NAPTR.js';
import { NS } from '../Packet/Types/NS.js';
import { NSEC } from '../Packet/Types/NSEC.js';
import { NSEC3 } from '../Packet/Types/NSEC3.js';
import { PTR } from '../Packet/Types/PTR.js';
import { RRSIG } from '../Packet/Types/RRSIG.js';
import { SOA } from '../Packet/Types/SOA.js';
import { SRV } from '../Packet/Types/SRV.js';
import { SSHFP } from '../Packet/Types/SSHFP.js';
import { SVCB } from '../Packet/Types/SVCB.js';
import { TLSA } from '../Packet/Types/TLSA.js';
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
    static _typeMnemonicToNumber(mnemonic, lineNumber) {
        const upper = mnemonic.toUpperCase();
        const generic = upper.match(/^TYPE(\d+)$/);
        if (generic) {
            return parseInt(generic[1], 10);
        }
        const value = PacketTypes[upper];
        if (typeof value === 'number') {
            return value;
        }
        throw new Error(`line ${lineNumber}: unknown record type mnemonic ${mnemonic}`);
    }
    static _base32hexDecode(input) {
        const cleaned = input.toUpperCase().replace(/=+$/u, '').replace(/\s+/gu, '');
        const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
        const out = [];
        let buffer = 0;
        let bitsLeft = 0;
        for (const ch of cleaned) {
            const idx = alphabet.indexOf(ch);
            if (idx < 0) {
                throw new Error(`invalid base32hex character "${ch}"`);
            }
            buffer = (buffer << 5) | idx;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                out.push((buffer >> bitsLeft) & 0xFF);
            }
        }
        return Buffer.from(out);
    }
    static _parseRdata(typeStr, rdata, origin, lineNumber) {
        const v = (n) => rdata[n].value;
        const fqdn = (raw) => ZoneParser._qualifyName(raw, origin);
        const need = (n, label) => {
            if (rdata.length < n) {
                throw new Error(`line ${lineNumber}: ${label} needs ${n} fields`);
            }
        };
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
                const parts = rdata.map((t) => t.value);
                return new TXT(parts.length === 1 ? parts[0] : parts);
            }
            case 'SOA': {
                need(7, 'SOA');
                return new SOA(fqdn(v(0)), fqdn(v(1)), parseInt(v(2), 10), ZoneParser._parseTtl(v(3)), ZoneParser._parseTtl(v(4)), ZoneParser._parseTtl(v(5)), ZoneParser._parseTtl(v(6)));
            }
            case 'SRV': {
                need(4, 'SRV');
                return new SRV(parseInt(v(0), 10), parseInt(v(1), 10), parseInt(v(2), 10), fqdn(v(3)));
            }
            case 'CAA': {
                need(3, 'CAA (flag tag value)');
                const flag = parseInt(v(0), 10);
                const tag = v(1);
                const value = rdata[2].quoted ? rdata[2].value : rdata.slice(2).map((t) => t.value).join(' ');
                return new CAA(flag, tag, value);
            }
            case 'DNSKEY': {
                need(4, 'DNSKEY (flags protocol algorithm key)');
                const flags = parseInt(v(0), 10);
                const protocol = parseInt(v(1), 10);
                const algorithm = parseInt(v(2), 10);
                const key = rdata.slice(3).map((t) => t.value).join('');
                return new DNSKEY(flags, protocol, algorithm, key);
            }
            case 'DS': {
                need(4, 'DS (keyTag algorithm digestType digest)');
                const keyTag = parseInt(v(0), 10);
                const algorithm = parseInt(v(1), 10);
                const digestType = parseInt(v(2), 10);
                const digest = rdata.slice(3).map((t) => t.value).join('').toLowerCase();
                return new DS(keyTag, algorithm, digestType, digest);
            }
            case 'SSHFP': {
                need(3, 'SSHFP (algorithm fpType fingerprint)');
                const algorithm = parseInt(v(0), 10);
                const fpType = parseInt(v(1), 10);
                const fingerprint = rdata.slice(2).map((t) => t.value).join('').toLowerCase();
                return new SSHFP(algorithm, fpType, fingerprint);
            }
            case 'TLSA': {
                need(4, 'TLSA (usage selector matchingType cert)');
                const usage = parseInt(v(0), 10);
                const selector = parseInt(v(1), 10);
                const matchingType = parseInt(v(2), 10);
                const cert = rdata.slice(3).map((t) => t.value).join('').toLowerCase();
                return new TLSA(usage, selector, matchingType, cert);
            }
            case 'NAPTR': {
                need(6, 'NAPTR (order pref flags services regexp replacement)');
                const order = parseInt(v(0), 10);
                const preference = parseInt(v(1), 10);
                const flags = rdata[2].value;
                const services = rdata[3].value;
                const regexp = rdata[4].value;
                const replacement = fqdn(rdata[5].value);
                return new NAPTR(order, preference, flags, services, regexp, replacement);
            }
            case 'NSEC': {
                need(1, 'NSEC (nextDomain types…)');
                const nextDomain = fqdn(v(0));
                const types = rdata.slice(1).map((t) => ZoneParser._typeMnemonicToNumber(t.value, lineNumber));
                return new NSEC(nextDomain, types);
            }
            case 'NSEC3': {
                need(5, 'NSEC3 (hashAlg flags iterations salt nextHashed types…)');
                const hashAlgorithm = parseInt(v(0), 10);
                const flags = parseInt(v(1), 10);
                const iterations = parseInt(v(2), 10);
                const saltRaw = v(3);
                const salt = saltRaw === '-' ? '' : saltRaw.toLowerCase();
                const nextHashedOwner = ZoneParser._base32hexDecode(v(4)).toString('hex');
                const types = rdata.slice(5).map((t) => ZoneParser._typeMnemonicToNumber(t.value, lineNumber));
                return new NSEC3(hashAlgorithm, flags, iterations, salt, nextHashedOwner, types);
            }
            case 'RRSIG': {
                need(9, 'RRSIG (typeCovered alg labels origTtl exp inc keyTag signer signature)');
                const sigType = ZoneParser._typeMnemonicToNumber(v(0), lineNumber);
                const algorithm = parseInt(v(1), 10);
                const labels = parseInt(v(2), 10);
                const originalTtl = ZoneParser._parseTtl(v(3));
                const expiration = v(4);
                const inception = v(5);
                const keyTag = parseInt(v(6), 10);
                const signer = fqdn(v(7));
                const signature = rdata.slice(8).map((t) => t.value).join('');
                return new RRSIG(sigType, algorithm, labels, originalTtl, expiration, inception, keyTag, signer, signature);
            }
            case 'SVCB':
                return ZoneParser._parseSvcb(rdata, origin, lineNumber, false);
            case 'HTTPS':
                return ZoneParser._parseSvcb(rdata, origin, lineNumber, true);
            default:
                throw new Error(`line ${lineNumber}: unsupported record type ${typeStr}`);
        }
    }
    static _parseSvcb(rdata, origin, lineNumber, isHttps) {
        if (rdata.length < 2) {
            throw new Error(`line ${lineNumber}: SVCB/HTTPS needs priority + target`);
        }
        const priority = parseInt(rdata[0].value, 10);
        if (!Number.isInteger(priority) || priority < 0 || priority > 0xFFFF) {
            throw new Error(`line ${lineNumber}: SVCB/HTTPS invalid priority`);
        }
        const targetRaw = rdata[1].value;
        const target = targetRaw === '.' ? '' : ZoneParser._qualifyName(targetRaw, origin);
        const params = {};
        for (let i = 2; i < rdata.length; i++) {
            const token = rdata[i].value;
            const eqIdx = token.indexOf('=');
            let key;
            let value;
            if (eqIdx < 0) {
                key = token;
                value = null;
            }
            else {
                key = token.slice(0, eqIdx);
                value = token.slice(eqIdx + 1);
                if (value.length === 0 && i + 1 < rdata.length && rdata[i + 1].quoted) {
                    i++;
                    value = rdata[i].value;
                }
            }
            ZoneParser._applySvcParam(params, key, value, lineNumber);
        }
        return isHttps ? new HTTPS(priority, target, params) : new SVCB(priority, target, params);
    }
    static _applySvcParam(params, key, value, lineNumber) {
        switch (key) {
            case 'mandatory':
                params.mandatory = ZoneParser._splitList(value, key, lineNumber)
                    .map((m) => ZoneParser._svcParamKeyToNumber(m, lineNumber));
                return;
            case 'alpn':
                params.alpn = ZoneParser._splitList(value, key, lineNumber);
                return;
            case 'no-default-alpn':
                params.noDefaultAlpn = true;
                return;
            case 'port':
                if (value === null) {
                    throw new Error(`line ${lineNumber}: SVCB port= requires a value`);
                }
                params.port = parseInt(value, 10);
                return;
            case 'ipv4hint':
                params.ipv4hint = ZoneParser._splitList(value, key, lineNumber);
                return;
            case 'ipv6hint':
                params.ipv6hint = ZoneParser._splitList(value, key, lineNumber);
                return;
            case 'ech':
                if (value === null) {
                    throw new Error(`line ${lineNumber}: SVCB ech= requires a value`);
                }
                params.ech = Buffer.from(value, 'base64');
                return;
            case 'dohpath':
                if (value === null) {
                    throw new Error(`line ${lineNumber}: SVCB dohpath= requires a value`);
                }
                params.dohpath = value;
                return;
            default: {
                const generic = key.match(/^key(\d+)$/u);
                if (!generic) {
                    throw new Error(`line ${lineNumber}: unknown SvcParamKey "${key}"`);
                }
                const numericKey = parseInt(generic[1], 10);
                const entry = {
                    key: numericKey,
                    value: value === null ? Buffer.alloc(0) : Buffer.from(value, 'utf8'),
                };
                if (!params.unknown) {
                    params.unknown = [];
                }
                params.unknown.push(entry);
            }
        }
    }
    static _splitList(value, key, lineNumber) {
        if (value === null || value.length === 0) {
            throw new Error(`line ${lineNumber}: SVCB ${key}= requires a value`);
        }
        return value.split(',');
    }
    static _svcParamKeyToNumber(name, lineNumber) {
        switch (name) {
            case 'mandatory':
                return 0;
            case 'alpn':
                return 1;
            case 'no-default-alpn':
                return 2;
            case 'port':
                return 3;
            case 'ipv4hint':
                return 4;
            case 'ech':
                return 5;
            case 'ipv6hint':
                return 6;
            case 'dohpath':
                return 7;
            default: {
                const generic = name.match(/^key(\d+)$/u);
                if (generic) {
                    return parseInt(generic[1], 10);
                }
                throw new Error(`line ${lineNumber}: unknown SvcParamKey mnemonic "${name}"`);
            }
        }
    }
}
//# sourceMappingURL=ZoneParser.js.map