import fs from 'fs';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
export class HostsFileWatchHandle {
    _hostsFile;
    _path;
    _debounceMs;
    _onReload;
    _onError;
    _watcher;
    _debounceTimer;
    _closed;
    constructor(hostsFile, path, options) {
        this._hostsFile = hostsFile;
        this._path = path;
        this._debounceMs = options.debounceMs ?? 100;
        this._onReload = options.onReload;
        this._onError = options.onError;
        this._watcher = null;
        this._debounceTimer = null;
        this._closed = false;
        this._openWatcher();
    }
    get path() {
        return this._path;
    }
    get closed() {
        return this._closed;
    }
    reloadNow() {
        if (this._debounceTimer !== null) {
            clearTimeout(this._debounceTimer);
            this._debounceTimer = null;
        }
        this._performReload();
    }
    close() {
        if (this._closed) {
            return;
        }
        this._closed = true;
        if (this._debounceTimer !== null) {
            clearTimeout(this._debounceTimer);
            this._debounceTimer = null;
        }
        if (this._watcher !== null) {
            this._watcher.close();
            this._watcher = null;
        }
    }
    _openWatcher() {
        if (this._closed) {
            return;
        }
        try {
            this._watcher = fs.watch(this._path, (eventType) => {
                this._scheduleReload(eventType);
            });
            this._watcher.on('error', (err) => {
                this._reportError(err);
            });
        }
        catch (err) {
            this._reportError(err);
        }
    }
    _scheduleReload(eventType) {
        if (this._closed) {
            return;
        }
        if (this._debounceTimer !== null) {
            clearTimeout(this._debounceTimer);
        }
        this._debounceTimer = setTimeout(() => {
            this._debounceTimer = null;
            this._performReload();
            if (eventType === 'rename') {
                if (this._watcher !== null) {
                    this._watcher.close();
                    this._watcher = null;
                }
                this._openWatcher();
            }
        }, this._debounceMs);
        if (typeof this._debounceTimer.unref === 'function') {
            this._debounceTimer.unref();
        }
    }
    _performReload() {
        try {
            this._hostsFile.reload(this._path);
            if (this._onReload !== undefined) {
                this._onReload(this._hostsFile);
            }
        }
        catch (err) {
            this._reportError(err);
        }
    }
    _reportError(err) {
        if (this._onError !== undefined) {
            this._onError(err);
            return;
        }
        if (err.code === 'ENOENT' || err.code === 'EACCES' || err.code === 'EPERM') {
            return;
        }
        process.emitWarning(`HostsFile.watch: ${err.message}`, 'HostsFileWatchWarning');
    }
}
export class HostsFile {
    static DEFAULT_PATH = '/etc/hosts';
    _entries;
    _byName;
    _ttl;
    _sourcePath;
    constructor(entries = [], options = {}) {
        this._entries = entries;
        this._ttl = Math.max(0, options.ttl ?? 0);
        this._byName = HostsFile._index(entries);
        this._sourcePath = null;
    }
    static parse(content, options = {}) {
        const entries = [];
        for (const rawLine of content.split(/\r?\n/u)) {
            const stripped = HostsFile._stripComment(rawLine).trim();
            if (stripped.length === 0) {
                continue;
            }
            const tokens = stripped.split(/\s+/u);
            if (tokens.length < 2) {
                continue;
            }
            const address = tokens[0];
            const family = HostsFile._detectFamily(address);
            if (family === null) {
                continue;
            }
            const names = tokens.slice(1).map((n) => n.toLowerCase()).filter((n) => n.length > 0);
            if (names.length === 0) {
                continue;
            }
            entries.push({ address: address, family: family, names: names });
        }
        return new HostsFile(entries, options);
    }
    static fromFile(path = HostsFile.DEFAULT_PATH, options = {}) {
        const content = fs.readFileSync(path, 'utf8');
        const file = HostsFile.parse(content, options);
        file._sourcePath = path;
        return file;
    }
    get sourcePath() {
        return this._sourcePath;
    }
    reload(path) {
        const target = path ?? this._sourcePath;
        if (target === null || target === undefined) {
            throw new Error('HostsFile.reload: no source path — pass `path` or construct via fromFile()');
        }
        const content = fs.readFileSync(target, 'utf8');
        const parsed = HostsFile.parse(content, { ttl: this._ttl });
        this._entries = parsed._entries;
        this._byName = parsed._byName;
        this._sourcePath = target;
    }
    get entries() {
        return this._entries.slice();
    }
    lookup(name, type) {
        const normalized = HostsFile._normalizeName(name);
        const matches = this._byName.get(normalized);
        if (matches === undefined || matches.length === 0) {
            return { kind: 'miss' };
        }
        const records = [];
        for (const entry of matches) {
            if (type === PacketTypes.A && entry.family === 'ipv4') {
                records.push(new PacketResource(name, new A(entry.address), PacketClass.IN, this._ttl));
            }
            else if (type === PacketTypes.AAAA && entry.family === 'ipv6') {
                records.push(new PacketResource(name, new AAAA(entry.address), PacketClass.IN, this._ttl));
            }
        }
        if (records.length > 0) {
            return { kind: 'match', records: records };
        }
        return { kind: 'nodata' };
    }
    asResolverBackend(fallback) {
        return async (name, type, cls) => {
            const result = this.lookup(name, type);
            if (result.kind === 'miss') {
                return fallback(name, type, cls);
            }
            const synthesized = new Packet();
            synthesized.header.qr = 1;
            synthesized.header.aa = 1;
            synthesized.header.rcode = 0;
            synthesized.questions.push(new PacketQuestion(name, type, cls));
            if (result.kind === 'match') {
                synthesized.answers = result.records;
            }
            return synthesized;
        };
    }
    merge(other) {
        return new HostsFile([...this._entries, ...other._entries], { ttl: this._ttl });
    }
    watch(options = {}) {
        const target = options.path ?? this._sourcePath;
        if (target === null || target === undefined) {
            throw new Error('HostsFile.watch: no path — pass `options.path` or construct via fromFile()');
        }
        return new HostsFileWatchHandle(this, target, options);
    }
    static _index(entries) {
        const index = new Map();
        for (const entry of entries) {
            for (const name of entry.names) {
                const key = HostsFile._normalizeName(name);
                const bucket = index.get(key);
                if (bucket === undefined) {
                    index.set(key, [entry]);
                }
                else {
                    bucket.push(entry);
                }
            }
        }
        return index;
    }
    static _normalizeName(name) {
        const lower = name.toLowerCase();
        return lower.endsWith('.') ? lower.slice(0, -1) : lower;
    }
    static _stripComment(line) {
        const idx = line.indexOf('#');
        return idx === -1 ? line : line.slice(0, idx);
    }
    static _detectFamily(token) {
        if (token.includes(':')) {
            return HostsFile._isIpv6(token) ? 'ipv6' : null;
        }
        return HostsFile._isIpv4(token) ? 'ipv4' : null;
    }
    static _isIpv4(token) {
        const parts = token.split('.');
        if (parts.length !== 4) {
            return false;
        }
        for (const p of parts) {
            if (p.length === 0 || p.length > 3) {
                return false;
            }
            for (let i = 0; i < p.length; i++) {
                const code = p.charCodeAt(i);
                if (code < 48 || code > 57) {
                    return false;
                }
            }
            const n = Number.parseInt(p, 10);
            if (n < 0 || n > 255) {
                return false;
            }
        }
        return true;
    }
    static _isIpv6(token) {
        if (token.length === 0 || token.length > 45) {
            return false;
        }
        for (let i = 0; i < token.length; i++) {
            const c = token[i];
            if (c === ':' || c === '.') {
                continue;
            }
            const code = token.charCodeAt(i);
            const isDigit = code >= 48 && code <= 57;
            const isHexLower = code >= 97 && code <= 102;
            const isHexUpper = code >= 65 && code <= 70;
            if (!isDigit && !isHexLower && !isHexUpper) {
                return false;
            }
        }
        return token.includes(':');
    }
}
//# sourceMappingURL=HostsFile.js.map