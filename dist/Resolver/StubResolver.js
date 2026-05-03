import { PacketClass } from '../Packet/PacketClass.js';
import { RCODE } from './RecursiveResolver.js';
export class StubResolver {
    _resolver;
    _search;
    _ndots;
    constructor(options) {
        if (typeof options.resolver !== 'function') {
            throw new Error('StubResolver: options.resolver is required');
        }
        this._resolver = options.resolver;
        this._search = StubResolver._normalizeSearch(options.search ?? []);
        this._ndots = Math.max(0, options.ndots ?? 1);
    }
    static fromConfig(parsed, resolver) {
        const search = parsed.search.length > 0
            ? parsed.search
            : (parsed.domain !== undefined ? [parsed.domain] : []);
        return new StubResolver({
            resolver: resolver,
            search: search,
            ndots: parsed.options.ndots
        });
    }
    expand(name) {
        if (name.endsWith('.')) {
            return [name.slice(0, -1)];
        }
        if (this._search.length === 0 || this._ndots === 0) {
            return [name];
        }
        const dots = StubResolver._countDots(name);
        const withSuffixes = this._search.map((s) => `${name}.${s}`);
        if (dots >= this._ndots) {
            return [name, ...withSuffixes];
        }
        return [...withSuffixes, name];
    }
    async resolve(name, type, cls = PacketClass.IN) {
        const candidates = this.expand(name);
        if (candidates.length === 0) {
            throw new Error(`StubResolver.resolve: no candidates produced for "${name}"`);
        }
        let lastNxdomain = null;
        for (const candidate of candidates) {
            const response = await this._resolver(candidate, type, cls);
            if (response.header.rcode === RCODE.NXDOMAIN) {
                lastNxdomain = response;
                continue;
            }
            return response;
        }
        return lastNxdomain;
    }
    get search() {
        return this._search.slice();
    }
    get ndots() {
        return this._ndots;
    }
    static _normalizeSearch(list) {
        const seen = new Set();
        const out = [];
        for (const raw of list) {
            const stripped = raw.endsWith('.') ? raw.slice(0, -1) : raw;
            if (stripped.length === 0) {
                continue;
            }
            if (!seen.has(stripped)) {
                seen.add(stripped);
                out.push(stripped);
            }
        }
        return out;
    }
    static _countDots(name) {
        let count = 0;
        for (let i = 0; i < name.length; i++) {
            if (name[i] === '.') {
                count++;
            }
        }
        return count;
    }
}
//# sourceMappingURL=StubResolver.js.map