import dgram from 'dgram';
import { MDNS_MULTICAST_IPV4, MDNS_MULTICAST_IPV6, MDNS_PORT, MDNS_QU_BIT } from '../Client/MdnsClient.js';
import { Packet } from '../Packet/Packet.js';
export class MdnsServer {
    _socket;
    _multicastAddr;
    _port;
    _interfaceAddress;
    _joinMulticastGroup;
    _multicastAddress;
    constructor(options = {}) {
        const family = options.family ?? 'udp4';
        this._multicastAddr = options.multicastAddr
            ?? (family === 'udp6' ? MDNS_MULTICAST_IPV6 : MDNS_MULTICAST_IPV4);
        this._port = options.port ?? MDNS_PORT;
        this._interfaceAddress = options.interfaceAddress;
        this._joinMulticastGroup = options.joinMulticastGroup
            ?? MdnsServer._isMulticast(this._multicastAddr);
        this._multicastAddress = this._multicastAddr;
        this._socket = dgram.createSocket({
            type: family,
            reuseAddr: options.reuseAddr ?? true
        });
        this._socket.on('message', (data, rinfo) => {
            this._handle(data, rinfo);
        });
    }
    on(event, listener) {
        this._socket.on(event, listener);
        return this;
    }
    once(event, listener) {
        this._socket.once(event, listener);
        return this;
    }
    listen() {
        return new Promise((resolve, reject) => {
            const onError = (err) => {
                this._socket.off('error', onError);
                reject(err);
            };
            this._socket.once('error', onError);
            this._socket.bind(this._port, this._interfaceAddress, () => {
                this._socket.off('error', onError);
                if (this._joinMulticastGroup) {
                    try {
                        if (this._interfaceAddress !== undefined) {
                            this._socket.addMembership(this._multicastAddr, this._interfaceAddress);
                        }
                        else {
                            this._socket.addMembership(this._multicastAddr);
                        }
                    }
                    catch {
                    }
                }
                resolve();
            });
        });
    }
    close(callback) {
        this._socket.close(callback);
    }
    address() {
        return this._socket.address();
    }
    _handle(data, rinfo) {
        let parsed;
        try {
            parsed = Packet.parse(data);
        }
        catch (e) {
            this._socket.emit('requestError', e instanceof Error ? e : new Error(String(e)));
            return;
        }
        if (parsed.header.qr === 1) {
            return;
        }
        const send = this._buildSend(parsed, rinfo);
        this._socket.emit('request', parsed, send, rinfo, data);
    }
    _buildSend(request, rinfo) {
        return (msg, target = 'auto') => {
            const buf = msg instanceof Packet ? msg.toBuffer() : msg;
            const resolved = target === 'auto'
                ? (MdnsServer._anyQuestionHasQu(request) ? 'unicast' : 'multicast')
                : target;
            const destAddr = resolved === 'unicast' ? rinfo.address : this._multicastAddr;
            const destPort = resolved === 'unicast' ? rinfo.port : this._port;
            return new Promise((resolve, reject) => {
                this._socket.send(buf, destPort, destAddr, (err) => {
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve();
                    }
                });
            });
        };
    }
    static _anyQuestionHasQu(packet) {
        for (const q of packet.questions) {
            if ((q.class & MDNS_QU_BIT) !== 0) {
                return true;
            }
        }
        return false;
    }
    static _isMulticast(addr) {
        if (addr.includes(':')) {
            return addr.toLowerCase().startsWith('ff');
        }
        const firstOctet = Number.parseInt(addr.split('.')[0], 10);
        return firstOctet >= 224 && firstOctet <= 239;
    }
}
//# sourceMappingURL=MdnsServer.js.map