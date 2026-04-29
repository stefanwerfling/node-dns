import { Buffer } from 'buffer';
import * as fs from 'fs';
import * as path from 'path';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {CAA} from '../Packet/Types/CAA.js';
import {CNAME} from '../Packet/Types/CNAME.js';
import {CDNSKEY} from '../Packet/Types/CDNSKEY.js';
import {CDS} from '../Packet/Types/CDS.js';
import {DNAME} from '../Packet/Types/DNAME.js';
import {DNSKEY} from '../Packet/Types/DNSKEY.js';
import {DS} from '../Packet/Types/DS.js';
import {HTTPS} from '../Packet/Types/HTTPS.js';
import {MX} from '../Packet/Types/MX.js';
import {NAPTR} from '../Packet/Types/NAPTR.js';
import {NS} from '../Packet/Types/NS.js';
import {NSEC} from '../Packet/Types/NSEC.js';
import {NSEC3} from '../Packet/Types/NSEC3.js';
import {PTR} from '../Packet/Types/PTR.js';
import {RRSIG} from '../Packet/Types/RRSIG.js';
import {SOA} from '../Packet/Types/SOA.js';
import {SRV} from '../Packet/Types/SRV.js';
import {SSHFP} from '../Packet/Types/SSHFP.js';
import {SVCB, SvcParams, SvcParamUnknown} from '../Packet/Types/SVCB.js';
import {TLSA} from '../Packet/Types/TLSA.js';
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
 * Resolves an `$INCLUDE` directive's filename token to the file's text content.
 * Receives the literal token from the zone file and the current `basePath`
 * (directory of the file currently being parsed, if known).
 */
export type ZoneIncludeResolver = (filename: string, basePath: string|undefined) => string;

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

    /**
     * Base directory used when resolving relative `$INCLUDE` paths. Required
     * for filesystem-backed includes; optional when a custom `includeResolver`
     * is supplied (in which case the resolver decides how to interpret it).
     */
    basePath?: string;

    /**
     * Override how `$INCLUDE` filenames are resolved to file content. The
     * default reads from the filesystem via `fs.readFileSync`, treating the
     * path as relative to `basePath`. Provide a custom resolver to load
     * includes from a different source (test fixtures, archives, etc.).
     */
    includeResolver?: ZoneIncludeResolver;
};

/**
 * Parser for the RFC 1035 master file format ("zone file").
 *
 * Supports:
 *   - `;` comments, `( … )` multi-line records, `"…"` quoted strings
 *     with `\\` and `\"` escapes
 *   - `$ORIGIN`, `$TTL`, `$INCLUDE` directives
 *   - `@` shortcut for the current origin
 *   - TTL/class inheritance from the previous record
 *   - RDATA for A, AAAA, NS, CNAME, DNAME, PTR, MX, TXT, SOA, SRV, CAA,
 *     DNSKEY, DS, SSHFP, TLSA, NAPTR, NSEC, NSEC3, RRSIG, SVCB, HTTPS
 *
 * Not yet supported (intentional): generic-encoding `\#`.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc1035#section-5
 */
export class ZoneParser {

    public static parse(input: string, options: ZoneParseOptions = {}): ZoneParseResult {
        return ZoneParser._parseInternal(input, options, new Set());
    }

    /**
     * Implementation of `parse` that threads cycle-detection state through
     * recursive `$INCLUDE` calls. Each include creates a fresh nested state:
     * its `$ORIGIN`/`$TTL` directives do not leak back into the parent file
     * (RFC 1035 §5.1: "the new origin … reverts" once the include is read).
     * @protected
     */
    protected static _parseInternal(
        input: string,
        options: ZoneParseOptions,
        visitedFiles: Set<string>
    ): ZoneParseResult {
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

            if (first === '$INCLUDE') {
                if (line.tokens.length < 2) {
                    throw new Error(`line ${line.lineNumber}: $INCLUDE requires a file name`);
                }

                const includeFilename = line.tokens[1].value;
                const overrideToken = line.tokens.length >= 3 ? line.tokens[2].value : null;
                const includeOrigin = overrideToken === null
                    ? origin
                    : ZoneParser._absolute(overrideToken === '@' ? origin : overrideToken);
                const cycleKey = ZoneParser._resolveIncludePath(includeFilename, options.basePath);

                if (visitedFiles.has(cycleKey)) {
                    throw new Error(`line ${line.lineNumber}: $INCLUDE cycle detected for ${includeFilename}`);
                }

                const content = ZoneParser._loadInclude(includeFilename, options, cycleKey, line.lineNumber);
                const childVisited = new Set(visitedFiles);
                childVisited.add(cycleKey);
                const childOptions: ZoneParseOptions = {
                    origin: includeOrigin,
                    defaultTtl: defaultTtl,
                    basePath: path.dirname(cycleKey),
                    includeResolver: options.includeResolver,
                };
                const sub = ZoneParser._parseInternal(content, childOptions, childVisited);

                for (const r of sub.records) {
                    records.push(r);
                }

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
     * Resolve an `$INCLUDE` filename to an absolute path. Used both for
     * filesystem reads and as the cycle-detection key.
     * @protected
     */
    protected static _resolveIncludePath(filename: string, basePath: string|undefined): string {
        if (path.isAbsolute(filename)) {
            return path.normalize(filename);
        }

        return path.resolve(basePath ?? process.cwd(), filename);
    }

    /**
     * Load the contents of an included file, either via the caller-supplied
     * resolver or via the default `fs.readFileSync` (UTF-8). Errors are
     * rewrapped so the line number stays in the message.
     * @protected
     */
    protected static _loadInclude(
        filename: string,
        options: ZoneParseOptions,
        resolvedPath: string,
        lineNumber: number
    ): string {
        try {
            if (options.includeResolver) {
                return options.includeResolver(filename, options.basePath);
            }

            return fs.readFileSync(resolvedPath, 'utf8');
        } catch (err) {
            const reason = err instanceof Error ? err.message : String(err);
            throw new Error(`line ${lineNumber}: $INCLUDE failed to load ${filename}: ${reason}`);
        }
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
     * Look up the numeric type code for a presentation-form mnemonic
     * (e.g. "A" → 1, "AAAA" → 28). Also accepts the generic `TYPEnnn`
     * form from RFC 3597 for unknown / future types.
     * @protected
     */
    protected static _typeMnemonicToNumber(mnemonic: string, lineNumber: number): number {
        const upper = mnemonic.toUpperCase();
        const generic = upper.match(/^TYPE(\d+)$/);

        if (generic) {
            return parseInt(generic[1], 10);
        }

        const value = (PacketTypes as Record<string, number|string>)[upper];

        if (typeof value === 'number') {
            return value;
        }

        throw new Error(`line ${lineNumber}: unknown record type mnemonic ${mnemonic}`);
    }

    /**
     * Decode a base32hex string (RFC 4648 §7) into bytes. Whitespace and
     * trailing `=` padding are tolerated. Used by NSEC3 next-hashed-owner.
     * @protected
     */
    protected static _base32hexDecode(input: string): Buffer {
        const cleaned = input.toUpperCase().replace(/=+$/u, '').replace(/\s+/gu, '');
        const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
        const out: number[] = [];
        let buffer = 0;
        let bitsLeft = 0;

        for (const ch of cleaned) {
            const idx = alphabet.indexOf(ch);

            if (idx < 0) {
                throw new Error(`invalid base32hex character "${ch}"`);
            }

            // eslint-disable-next-line no-bitwise
            buffer = (buffer << 5) | idx;
            bitsLeft += 5;

            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                // eslint-disable-next-line no-bitwise
                out.push((buffer >> bitsLeft) & 0xFF);
            }
        }

        return Buffer.from(out);
    }

    /**
     * Dispatch to per-type RDATA parsers. Throws on unsupported types so the
     * caller knows to extend the parser rather than silently dropping data.
     * @protected
     */
    protected static _parseRdata(typeStr: string, rdata: ZoneToken[], origin: string, lineNumber: number): PacketType {
        const v = (n: number): string => rdata[n].value;
        const fqdn = (raw: string): string => ZoneParser._qualifyName(raw, origin);
        const need = (n: number, label: string): void => {
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
                // Concatenate all character-strings (each token is one).
                const parts = rdata.map((t) => t.value);
                return new TXT(parts.length === 1 ? parts[0] : parts);
            }

            case 'SOA': {
                need(7, 'SOA');

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
                need(4, 'SRV');

                return new SRV(
                    parseInt(v(0), 10),
                    parseInt(v(1), 10),
                    parseInt(v(2), 10),
                    fqdn(v(3))
                );
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

            case 'CDS': {
                // RFC 7344 — same RDATA shape as DS, different type code.
                need(4, 'CDS (keyTag algorithm digestType digest)');

                const keyTag = parseInt(v(0), 10);
                const algorithm = parseInt(v(1), 10);
                const digestType = parseInt(v(2), 10);
                const digest = rdata.slice(3).map((t) => t.value).join('').toLowerCase();
                return new CDS(keyTag, algorithm, digestType, digest);
            }

            case 'CDNSKEY': {
                // RFC 7344 — same RDATA shape as DNSKEY, different type code.
                need(4, 'CDNSKEY (flags protocol algorithm key)');

                const flags = parseInt(v(0), 10);
                const protocol = parseInt(v(1), 10);
                const algorithm = parseInt(v(2), 10);
                const key = rdata.slice(3).map((t) => t.value).join('');
                return new CDNSKEY(flags, protocol, algorithm, key);
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

    /**
     * Parse an SVCB / HTTPS RDATA token list (RFC 9460 §2.1):
     *   priority TargetName [SvcParams]
     *
     * Each SvcParam is `key=value`, `key="value with spaces"`, or a bare
     * `key` (boolean — currently only `no-default-alpn`). When a token ends
     * with `=` and is followed by a quoted token, the two are joined.
     * Comma-separated lists (e.g. `alpn=h2,h3`) are split on commas; values
     * that contain commas should be passed as multiple `key=` pairs in
     * structured form when needed.
     * @protected
     */
    protected static _parseSvcb(
        rdata: ZoneToken[],
        origin: string,
        lineNumber: number,
        isHttps: boolean
    ): SVCB {
        if (rdata.length < 2) {
            throw new Error(`line ${lineNumber}: SVCB/HTTPS needs priority + target`);
        }

        const priority = parseInt(rdata[0].value, 10);

        if (!Number.isInteger(priority) || priority < 0 || priority > 0xFFFF) {
            throw new Error(`line ${lineNumber}: SVCB/HTTPS invalid priority`);
        }

        const targetRaw = rdata[1].value;
        const target = targetRaw === '.' ? '' : ZoneParser._qualifyName(targetRaw, origin);
        const params: SvcParams = {};

        for (let i = 2; i < rdata.length; i++) {
            const token = rdata[i].value;
            const eqIdx = token.indexOf('=');
            let key: string;
            let value: string|null;

            if (eqIdx < 0) {
                key = token;
                value = null;
            } else {
                key = token.slice(0, eqIdx);
                value = token.slice(eqIdx + 1);

                // `key=` followed by a quoted token: glue them together so
                // `dohpath="/dns-query{?dns}"` round-trips correctly.
                if (value.length === 0 && i + 1 < rdata.length && rdata[i + 1].quoted) {
                    i++;
                    value = rdata[i].value;
                }
            }

            ZoneParser._applySvcParam(params, key, value, lineNumber);
        }

        return isHttps ? new HTTPS(priority, target, params) : new SVCB(priority, target, params);
    }

    /**
     * Apply a single `key=value` (or bare `key`) pair to a SvcParams object.
     * Unknown keys round-trip via the `unknown` array so the parser doesn't
     * have to know every IANA registration.
     * @protected
     */
    protected static _applySvcParam(
        params: SvcParams,
        key: string,
        value: string|null,
        lineNumber: number
    ): void {
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
                const entry: SvcParamUnknown = {
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

    /**
     * Convert a comma-separated SVCB value list to a string array. Throws
     * if the value is missing — the keys that use lists never tolerate an
     * empty value in presentation form.
     * @protected
     */
    protected static _splitList(value: string|null, key: string, lineNumber: number): string[] {
        if (value === null || value.length === 0) {
            throw new Error(`line ${lineNumber}: SVCB ${key}= requires a value`);
        }

        return value.split(',');
    }

    /**
     * Map a SVCB `mandatory` list entry to the numeric SvcParamKey. Accepts
     * the same mnemonics the encoder produces plus the generic `keyN` form.
     * @protected
     */
    protected static _svcParamKeyToNumber(name: string, lineNumber: number): number {
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