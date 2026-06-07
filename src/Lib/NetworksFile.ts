import fs from 'fs';
import {Buffer} from 'buffer';

/**
 * One entry parsed from `/etc/networks`: a canonical name plus the
 * IPv4 network address it points at, plus any aliases. Addresses are
 * normalized to the full 4-byte form (so the file's abbreviated
 * `127` becomes `127.0.0.0` here).
 */
export type NetworksEntry = {
    name: string;
    address: string;
    aliases: string[];
};

/**
 * Options for `NetworksFile.fromFile()`.
 */
export type NetworksFileOptions = {
    path?: string;
};

/**
 * `/etc/networks` reader — the `networks(5)` companion to
 * `/etc/hosts`. Maps human-readable network names to IPv4 network
 * addresses (e.g. `loopback 127.0.0.0`, `link-local 169.254.0.0`)
 * for tools that prefer to refer to subnets by symbolic name.
 *
 * Mostly used by routing tools and `getnetbyname(3)`/
 * `getnetbyaddr(3)` consumers; not part of the DNS resolution path
 * itself. dns2ts exposes the parser as a standalone utility so
 * callers can integrate it where it makes sense (reverse-name
 * pretty-printing, IP-to-network classification in observability
 * stacks).
 *
 * **IPv4 only** per `networks(5)`. Tolerant: comments via `#`,
 * malformed lines silently skipped, names lowercased on parse.
 * Abbreviated addresses (`127`, `192.168`, `192.168.1`) are
 * expanded to the full dotted-quad with trailing zero octets — the
 * historical convention from `getnetbyname(3)`.
 *
 * @docs https://man7.org/linux/man-pages/man5/networks.5.html
 */
export class NetworksFile {

    /**
     * Default path used by `fromFile()` when no override is given.
     */
    public static readonly DEFAULT_PATH: string = '/etc/networks';

    protected _entries: NetworksEntry[];
    protected _byName: Map<string, NetworksEntry>;
    protected _byAddress: Map<string, NetworksEntry>;
    protected _sourcePath: string | null;

    public constructor(entries: NetworksEntry[] = [], sourcePath: string | null = null) {
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

    /**
     * Parse `/etc/networks`-format content.
     *
     * @param {string} content
     * @return {NetworksFile}
     */
    public static parse(content: string): NetworksFile {
        const entries: NetworksEntry[] = [];

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

    /**
     * Read `/etc/networks` (or the supplied path) and parse it. Returns
     * an empty `NetworksFile` on `ENOENT` / `EACCES` / `EPERM` to match
     * glibc's tolerance; any other error propagates.
     *
     * @param {string} path
     * @return {NetworksFile}
     */
    public static fromFile(path: string = NetworksFile.DEFAULT_PATH): NetworksFile {
        let content: string;

        try {
            content = fs.readFileSync(path, 'utf8');
        } catch (e) {
            const err = e as NodeJS.ErrnoException;

            if (err.code === 'ENOENT' || err.code === 'EACCES' || err.code === 'EPERM') {
                return new NetworksFile([], path);
            }

            throw err;
        }

        const parsed = NetworksFile.parse(content);
        return new NetworksFile(parsed._entries, path);
    }

    /**
     * Expand a `networks(5)` short-form address (e.g. `127`, `10.0`,
     * `192.168.1`) into a full dotted-quad with trailing zero octets.
     * Returns `null` on malformed input — callers that want strict
     * validation must use `IpBytes.parseIPv4` separately.
     *
     * @param {string} address
     * @return {string|null}
     */
    protected static _expandAddress(address: string): string | null {
        const parts = address.split('.');

        if (parts.length === 0 || parts.length > 4) {
            return null;
        }

        const octets: number[] = [];

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

    /**
     * All parsed entries, in file order.
     *
     * @return {NetworksEntry[]}
     */
    public get entries(): NetworksEntry[] {
        return this._entries;
    }

    /**
     * Path the file was read from, or `null` if this instance came from
     * `parse()`.
     *
     * @return {string|null}
     */
    public get sourcePath(): string | null {
        return this._sourcePath;
    }

    /**
     * Look up a network by its name (case-insensitive). Aliases are
     * matched too, but the returned entry always reflects the canonical
     * name.
     *
     * @param {string} name
     * @return {NetworksEntry|null}
     */
    public lookupByName(name: string): NetworksEntry | null {
        return this._byName.get(name.toLowerCase()) ?? null;
    }

    /**
     * Look up a network by its address. Accepts a 4-byte `Buffer` or a
     * dotted-quad string (which is normalized to canonical form before
     * lookup so `127.0.0.0` and `127` both match).
     *
     * @param {string|Buffer} address
     * @return {NetworksEntry|null}
     */
    public lookupByAddress(address: string | Buffer): NetworksEntry | null {
        let key: string;

        if (Buffer.isBuffer(address)) {
            if (address.length !== 4) {
                return null;
            }

            key = `${address[0]}.${address[1]}.${address[2]}.${address[3]}`;
        } else {
            const normalized = NetworksFile._expandAddress(address);

            if (normalized === null) {
                return null;
            }

            key = normalized;
        }

        return this._byAddress.get(key) ?? null;
    }

    /**
     * Stack another `NetworksFile` on top of this one — earlier entries
     * win on collision (system-then-local override pattern). The
     * resulting instance is independent from the inputs.
     *
     * @param {NetworksFile} other
     * @return {NetworksFile}
     */
    public merge(other: NetworksFile): NetworksFile {
        const merged: NetworksEntry[] = [...this._entries];
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