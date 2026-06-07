import { IpBytes } from '../Lib/IpBytes.js';
import { Packet } from '../Packet/Packet.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { EDNS } from '../Packet/Types/EDNS.js';
import { EdnsCookie } from '../Packet/Types/EdnsCookie.js';
export const BADCOOKIE_RCODE = 23;
const REFUSED_RCODE = 5;
export class CookieGuard {
    _config;
    constructor(options) {
        this._config = {
            secret: options.secret,
            mode: options.mode ?? 'lenient',
            maxAgeSeconds: options.maxAgeSeconds ?? 3600,
            udpPayloadSize: options.udpPayloadSize ?? 1232
        };
    }
    get mode() {
        return this._config.mode;
    }
    evaluate(message, clientAddress) {
        const incoming = CookieGuard.findCookieOption(message);
        if (incoming === null) {
            if (this._config.mode === 'strict') {
                return { action: 'refused', reason: 'no-cookie-strict' };
            }
            return { action: 'allow', clientCookie: null, freshServerCookie: null };
        }
        let clientIpBytes;
        try {
            clientIpBytes = IpBytes.parse(clientAddress);
        }
        catch {
            return { action: 'refused', reason: 'invalid-cookie' };
        }
        const fresh = EdnsCookie.computeServerCookie(incoming.clientCookie, clientIpBytes, this._config.secret);
        if (incoming.serverCookie === null) {
            return {
                action: 'badcookie',
                reason: 'no-server-cookie',
                clientCookie: incoming.clientCookie,
                freshServerCookie: fresh
            };
        }
        const valid = EdnsCookie.verifyServerCookie(incoming.serverCookie, incoming.clientCookie, clientIpBytes, this._config.secret, this._config.maxAgeSeconds > 0 ? { maxAgeSeconds: this._config.maxAgeSeconds } : {});
        if (!valid) {
            return {
                action: 'badcookie',
                reason: 'invalid-cookie',
                clientCookie: incoming.clientCookie,
                freshServerCookie: fresh
            };
        }
        return {
            action: 'allow',
            clientCookie: incoming.clientCookie,
            freshServerCookie: fresh
        };
    }
    buildCookieOpt(clientCookie, serverCookie, extTtl) {
        const rdata = clientCookie !== null
            ? [new EdnsCookie(clientCookie, serverCookie ?? undefined)]
            : [];
        return new PacketResource('', new EDNS(rdata), this._config.udpPayloadSize, extTtl);
    }
    attachOrReplaceCookieOpt(response, clientCookie, serverCookie) {
        const existingIdx = response.additionals.findIndex((r) => r.packetType.type === PacketTypes.EDNS);
        if (existingIdx === -1) {
            response.additionals.push(this.buildCookieOpt(clientCookie, serverCookie, 0));
            return;
        }
        const opt = response.additionals[existingIdx].packetType;
        const otherOptions = opt.rdata.filter((o) => !(o instanceof EdnsCookie));
        opt.rdata = [...otherOptions, new EdnsCookie(clientCookie, serverCookie)];
    }
    buildBadCookieResponse(request, clientCookie, freshServerCookie) {
        const response = new Packet();
        response.header.id = request.header.id;
        response.header.qr = 1;
        response.header.opcode = request.header.opcode;
        response.header.rd = request.header.rd;
        response.header.rcode = BADCOOKIE_RCODE & 0x0F;
        response.questions = request.questions.map((q) => new PacketQuestion(q.name, q.type, q.class));
        response.additionals.push(this.buildCookieOpt(clientCookie, freshServerCookie, (BADCOOKIE_RCODE >> 4) << 24));
        return response;
    }
    buildRefusedResponse(request) {
        const response = new Packet();
        response.header.id = request.header.id;
        response.header.qr = 1;
        response.header.opcode = request.header.opcode;
        response.header.rd = request.header.rd;
        response.header.rcode = REFUSED_RCODE;
        response.questions = request.questions.map((q) => new PacketQuestion(q.name, q.type, q.class));
        return response;
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
}
//# sourceMappingURL=CookieGuard.js.map