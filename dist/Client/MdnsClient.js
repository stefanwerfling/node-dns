import dgram from 'dgram';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
export const MDNS_MULTICAST_IPV4 = '224.0.0.251';
export const MDNS_MULTICAST_IPV6 = 'ff02::fb';
export const MDNS_PORT = 5353;
export const MDNS_QU_BIT = 0x8000;
export const MDNS_CACHE_FLUSH_BIT = 0x8000;
export class MdnsClient {
    static makeQuery(name, type, cls = PacketClass.IN, unicastResponse = false) {
        const packet = new Packet();
        packet.header.id = 0;
        packet.header.rd = 0;
        const effectiveClass = unicastResponse ? cls | MDNS_QU_BIT : cls;
        packet.questions.push(new PacketQuestion(name, type, effectiveClass));
        return packet;
    }
    static request(options = {}) {
        const family = options.family ?? 'udp4';
        const multicastAddr = options.multicastAddr
            ?? (family === 'udp6' ? MDNS_MULTICAST_IPV6 : MDNS_MULTICAST_IPV4);
        const port = options.port ?? MDNS_PORT;
        const timeoutMs = options.timeoutMs ?? 1000;
        const joinGroup = options.joinMulticastGroup
            ?? MdnsClient._isMulticast(multicastAddr);
        return (name, type, cls = PacketClass.IN) => {
            return new Promise((resolve, reject) => {
                const socket = dgram.createSocket({ type: family, reuseAddr: true });
                const responses = [];
                let settled = false;
                let timer = null;
                const finish = (err) => {
                    if (settled) {
                        return;
                    }
                    settled = true;
                    if (timer !== null) {
                        clearTimeout(timer);
                    }
                    try {
                        socket.close();
                    }
                    catch {
                    }
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve(responses);
                    }
                };
                socket.on('error', (err) => finish(err));
                socket.on('message', (msg, rinfo) => {
                    let parsed;
                    try {
                        parsed = Packet.parse(msg);
                    }
                    catch {
                        return;
                    }
                    if (parsed.header.qr !== 1) {
                        return;
                    }
                    responses.push({
                        packet: parsed,
                        answers: parsed.answers,
                        additionals: parsed.additionals,
                        sender: { address: rinfo.address, port: rinfo.port }
                    });
                });
                const startQuery = () => {
                    if (joinGroup) {
                        try {
                            if (options.interfaceAddress !== undefined) {
                                socket.addMembership(multicastAddr, options.interfaceAddress);
                            }
                            else {
                                socket.addMembership(multicastAddr);
                            }
                        }
                        catch {
                        }
                    }
                    const query = MdnsClient.makeQuery(name, type, cls, options.unicastResponse);
                    socket.send(query.toBuffer(), port, multicastAddr, (err) => {
                        if (err) {
                            finish(err);
                            return;
                        }
                        timer = setTimeout(() => finish(null), timeoutMs);
                        timer.unref?.();
                    });
                };
                socket.bind(0, options.interfaceAddress, startQuery);
            });
        };
    }
    static _isMulticast(addr) {
        if (addr.includes(':')) {
            return addr.toLowerCase().startsWith('ff');
        }
        const firstOctet = Number.parseInt(addr.split('.')[0], 10);
        return firstOctet >= 224 && firstOctet <= 239;
    }
}
//# sourceMappingURL=MdnsClient.js.map