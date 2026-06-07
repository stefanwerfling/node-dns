import { PacketTypes } from '../Packet/PacketTypes.js';
import { EDNS } from '../Packet/Types/EDNS.js';
import { EdnsCookie } from '../Packet/Types/EdnsCookie.js';
const BADCOOKIE_RCODE = 23;
const BADCOOKIE_HEADER_LOW = BADCOOKIE_RCODE & 0xF;
const BADCOOKIE_EXT_HI = (BADCOOKIE_RCODE >> 4) & 0xFF;
export class ClientCookieJar {
    _entries = new Map();
    static key(host, port) {
        return `${host}:${port}`;
    }
    getOrCreate(host, port) {
        const key = ClientCookieJar.key(host, port);
        const existing = this._entries.get(key);
        if (existing) {
            return existing;
        }
        const entry = {
            clientCookie: EdnsCookie.generateClientCookie(),
            serverCookie: null
        };
        this._entries.set(key, entry);
        return entry;
    }
    peek(host, port) {
        return this._entries.get(ClientCookieJar.key(host, port)) ?? null;
    }
    learn(host, port, serverCookie) {
        if (serverCookie === null) {
            return;
        }
        const entry = this.getOrCreate(host, port);
        entry.serverCookie = serverCookie;
    }
    forget(host, port) {
        this._entries.delete(ClientCookieJar.key(host, port));
    }
    clear() {
        this._entries.clear();
    }
    size() {
        return this._entries.size;
    }
    attachTo(query, host, port) {
        const entry = this.getOrCreate(host, port);
        const cookieOption = new EdnsCookie(entry.clientCookie, entry.serverCookie ?? undefined);
        const optIdx = query.additionals.findIndex((r) => r.packetType.type === PacketTypes.EDNS);
        if (optIdx === -1) {
            query.additionals.push(EDNS.createResource([cookieOption]));
            return;
        }
        const opt = query.additionals[optIdx].packetType;
        const others = opt.rdata.filter((o) => !(o instanceof EdnsCookie));
        opt.rdata = [...others, cookieOption];
    }
    learnFromResponse(response, host, port) {
        const cookie = ClientCookieJar.findCookieOption(response);
        if (cookie && cookie.serverCookie) {
            this.learn(host, port, cookie.serverCookie);
        }
        return cookie;
    }
    static findCookieOption(message) {
        for (const r of message.additionals) {
            if (r.packetType.type !== PacketTypes.EDNS) {
                continue;
            }
            for (const opt of r.packetType.rdata) {
                if (opt instanceof EdnsCookie) {
                    return opt;
                }
            }
        }
        return null;
    }
    static extendedRcode(response) {
        const opt = response.additionals.find((r) => r.packetType.type === PacketTypes.EDNS);
        const headerLow = response.header.rcode & 0xF;
        if (!opt) {
            return headerLow;
        }
        const extHi = (opt.ttl >>> 24) & 0xFF;
        return (extHi << 4) | headerLow;
    }
    static isBadCookie(response) {
        if ((response.header.rcode & 0xF) !== BADCOOKIE_HEADER_LOW) {
            return false;
        }
        const opt = response.additionals.find((r) => r.packetType.type === PacketTypes.EDNS);
        if (!opt) {
            return false;
        }
        return ((opt.ttl >>> 24) & 0xFF) === BADCOOKIE_EXT_HI;
    }
}
//# sourceMappingURL=ClientCookieJar.js.map