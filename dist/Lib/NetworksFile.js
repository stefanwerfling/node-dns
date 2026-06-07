import fs from 'fs';
import { Buffer } from 'buffer';
export class NetworksFile {
    static DEFAULT_PATH = '/etc/networks';
    _entries;
    _byName;
    _byAddress;
    _sourcePath;
    constructor(entries = [], sourcePath = null) {
        this._entries = entries;
        this._sourcePath = sourcePath;
        this._byName = new Map();
        this._byAddress = new Map();
        for (const entry of entries) {
            this._byName.set(entry.name, entry);
            for (const alias of entry.aliases) {
                this._byName.set(alias, entry);
            }
            this._byAddress.set(entry.address, entry);
        }
    }
    static parse(content) {
        const entries = [];
        for (const rawLine of content.split(/\r?\n/u)) {
            const noComment = rawLine.split('#', 1)[0];
            const trimmed = noComment.trim();
            if (trimmed.length === 0) {
                continue;
            }
            const tokens = trimmed.split(/\s+/u);
            if (tokens.length < 2) {
                continue;
            }
            const expanded = NetworksFile._expandAddress(tokens[1]);
            if (expanded === null) {
                continue;
            }
            entries.push({
                name: tokens[0].toLowerCase(),
                address: expanded,
                aliases: tokens.slice(2).map((a) => a.toLowerCase())
            });
        }
        return new NetworksFile(entries);
    }
    static fromFile(path = NetworksFile.DEFAULT_PATH) {
        let content;
        try {
            content = fs.readFileSync(path, 'utf8');
        }
        catch (e) {
            const err = e;
            if (err.code === 'ENOENT' || err.code === 'EACCES' || err.code === 'EPERM') {
                return new NetworksFile([], path);
            }
            throw err;
        }
        const parsed = NetworksFile.parse(content);
        return new NetworksFile(parsed._entries, path);
    }
    static _expandAddress(address) {
        const parts = address.split('.');
        if (parts.length === 0 || parts.length > 4) {
            return null;
        }
        const octets = [];
        for (const p of parts) {
            if (!/^\d+$/u.test(p)) {
                return null;
            }
            const n = parseInt(p, 10);
            if (n < 0 || n > 255) {
                return null;
            }
            octets.push(n);
        }
        while (octets.length < 4) {
            octets.push(0);
        }
        return octets.join('.');
    }
    get entries() {
        return this._entries;
    }
    get sourcePath() {
        return this._sourcePath;
    }
    lookupByName(name) {
        return this._byName.get(name.toLowerCase()) ?? null;
    }
    lookupByAddress(address) {
        let key;
        if (Buffer.isBuffer(address)) {
            if (address.length !== 4) {
                return null;
            }
            key = `${address[0]}.${address[1]}.${address[2]}.${address[3]}`;
        }
        else {
            const normalized = NetworksFile._expandAddress(address);
            if (normalized === null) {
                return null;
            }
            key = normalized;
        }
        return this._byAddress.get(key) ?? null;
    }
    merge(other) {
        const merged = [...this._entries];
        const seenNames = new Set(this._entries.map((e) => e.name));
        const seenAddresses = new Set(this._entries.map((e) => e.address));
        for (const entry of other._entries) {
            if (seenNames.has(entry.name) || seenAddresses.has(entry.address)) {
                continue;
            }
            merged.push(entry);
            seenNames.add(entry.name);
            seenAddresses.add(entry.address);
        }
        return new NetworksFile(merged);
    }
}
//# sourceMappingURL=NetworksFile.js.map