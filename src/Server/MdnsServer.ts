import {Buffer} from 'buffer';
import dgram from 'dgram';
import {AddressInfo} from 'net';
import {
    MDNS_MULTICAST_IPV4,
    MDNS_MULTICAST_IPV6,
    MDNS_PORT,
    MDNS_QU_BIT
} from '../Client/MdnsClient.js';
import {Packet} from '../Packet/Packet.js';

/**
 * `send` payload accepted by the mDNS request handler. mDNS responses
 * are single-packet (no streaming), so we keep the surface tight:
 * either a `Packet` or pre-encoded bytes.
 */
export type MdnsSendable = Packet | Buffer;

/**
 * Where the response should go. mDNS is a multicast protocol but RFC
 * 6762 §6.7 carves out the QU (query unicast) case where the
 * responder is asked to reply unicast to the source port.
 *
 *  - `'auto'` (default) — multicast unless **any** question on the
 *    request had the QU bit set, in which case unicast back to the
 *    source.
 *  - `'multicast'` — always multicast, ignore QU.
 *  - `'unicast'` — always unicast back to the source `rinfo`.
 */
export type MdnsResponseTarget = 'auto' | 'multicast' | 'unicast';

/**
 * Handler signature mirrors the rest of the server family — the 4th
 * argument is the raw post-validation buffer for TSIG (RFC 8945)
 * verification, even though TSIG over multicast is rare.
 */
export type MdnsRequestListener = (
    msg: Packet,
    send: (msg: MdnsSendable, target?: MdnsResponseTarget) => Promise<void>,
    rinfo: dgram.RemoteInfo,
    rawRequest: Buffer
) => void;

/**
 * Constructor options for `MdnsServer`.
 */
export type MdnsServerOptions = {
    /**
     * Multicast group to join + send multicast responses to.
     * Default: `224.0.0.251` for `'udp4'`, `ff02::fb` for `'udp6'`.
     */
    multicastAddr?: string;

    /**
     * Bind port. RFC 6762 §3 fixes mDNS at 5353; tests use 0 to bind
     * an ephemeral port and a custom multicastAddr.
     */
    port?: number;

    /**
     * Address family. Default: `'udp4'`.
     */
    family?: 'udp4' | 'udp6';

    /**
     * Local interface address to bind on. Default: let the OS pick.
     */
    interfaceAddress?: string;

    /**
     * Whether to attempt joining the multicast group on `listen()`.
     * Default: true when `multicastAddr` is in the multicast range
     * (224.0.0.0/4 or ff00::/8), false otherwise. Tests set this
     * implicitly to `false` by passing a unicast `multicastAddr`
     * (e.g. `127.0.0.1`).
     */
    joinMulticastGroup?: boolean;

    /**
     * Set `SO_REUSEADDR` on the socket. mDNS responders run alongside
     * `avahi-daemon` / `mDNSResponder` on most desktops, so reuseAddr
     * is usually wanted. Default: true.
     */
    reuseAddr?: boolean;
};

/**
 * Multicast DNS server (RFC 6762).
 *
 * Listens on the link-local multicast group (`224.0.0.251:5353`
 * IPv4 / `[ff02::fb]:5353` IPv6) and emits `request` events shaped
 * like every other server in the project — `(packet, send, client,
 * rawRequest)`. The handler decides what to respond with; the server
 * doesn't ship a record store.
 *
 * Response routing follows RFC 6762 §6.7: by default, replies are
 * **multicast** (every device on the segment hears them and can
 * cache the answer), except when any question on the original query
 * carried the QU bit (top bit of QCLASS, §5.4) — in that case the
 * response is **unicast** back to the source port. Handlers can
 * override the target via the second argument to `send()`.
 *
 * The server filters out `qr=1` traffic (other devices' responses)
 * and only fires `request` for actual queries — the multicast group
 * sees a lot of unrelated chatter.
 *
 * **What this server does *not* do:**
 *
 * - **Probing / conflict resolution** (RFC 6762 §8). A real-world
 *   responder must probe before claiming a name and re-probe on
 *   conflict; that's an application-level concern that depends on
 *   what records you're announcing. The server gives you the wire
 *   primitives — composition is on you.
 * - **Goodbye announcements** (TTL=0 sends on shutdown, §10.1). The
 *   handler can construct and send these via `send()`; the server
 *   doesn't synthesize them automatically.
 * - **Continuous announcements**. Same.
 *
 * Tests can drive the server over `127.0.0.1` instead of joining a
 * real multicast group: when the configured `multicastAddr` is
 * unicast, `joinMulticastGroup` defaults to `false`, the bind
 * works on a private port, and the server behaves like a regular
 * UDP listener.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc6762
 */
export class MdnsServer {

    /**
     * @protected
     */
    protected _socket: dgram.Socket;

    /**
     * @protected
     */
    protected _multicastAddr: string;

    /**
     * @protected
     */
    protected _port: number;

    /**
     * @protected
     */
    protected _interfaceAddress?: string;

    /**
     * @protected
     */
    protected _joinMulticastGroup: boolean;

    /**
     * @protected
     */
    protected _multicastAddress: string;

    /**
     * @param {MdnsServerOptions} options
     */
    public constructor(options: MdnsServerOptions = {}) {
        const family: 'udp4' | 'udp6' = options.family ?? 'udp4';

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

    /**
     * `request` listener — fires for every parsed *query* received on
     * the multicast group. Responses (qr=1) and malformed datagrams
     * are silently filtered.
     *
     * @param {string} event
     * @param {MdnsRequestListener} listener
     * @return {this}
     */
    public on(event: 'request', listener: MdnsRequestListener): this;

    /**
     * `requestError` fires when parsing a received datagram fails.
     * Useful for metrics; mDNS multicast groups carry plenty of
     * unrelated traffic that may not be valid DNS.
     *
     * @param {string} event
     * @param {(err: unknown) => void} listener
     * @return {this}
     */
    public on(event: 'requestError', listener: (err: unknown) => void): this;

    /**
     * @param {string} event
     * @param {(...args: any[]) => void} listener
     * @return {this}
     */
    public on(event: string, listener: (...args: any[]) => void): this {
        this._socket.on(event, listener);
        return this;
    }

    /**
     * once
     * @param {string} event
     * @param {(...args: any[]) => void} listener
     * @return {this}
     */
    public once(event: string, listener: (...args: any[]) => void): this {
        this._socket.once(event, listener);
        return this;
    }

    /**
     * Bind the socket and (optionally) join the multicast group.
     * Resolves once the socket is bound.
     *
     * @return {Promise<void>}
     */
    public listen(): Promise<void> {
        return new Promise((resolve, reject) => {
            const onError = (err: Error): void => {
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
                        } else {
                            this._socket.addMembership(this._multicastAddr);
                        }
                    } catch {
                        // Joining can fail in test / non-multicast
                        // environments; the listener still works as a
                        // unicast UDP server on the bound port.
                    }
                }

                resolve();
            });
        });
    }

    /**
     * close
     * @param {() => void} callback
     */
    public close(callback?: () => void): void {
        this._socket.close(callback);
    }

    /**
     * Return the address of the bound socket.
     *
     * @return {AddressInfo}
     */
    public address(): AddressInfo {
        return this._socket.address() as AddressInfo;
    }

    /**
     * Handle one incoming datagram: filter responses, parse, fire the
     * request event with a response callback bound to this packet's
     * source.
     * @param {Buffer} data
     * @param {dgram.RemoteInfo} rinfo
     * @protected
     */
    protected _handle(data: Buffer, rinfo: dgram.RemoteInfo): void {
        let parsed: Packet;

        try {
            parsed = Packet.parse(data);
        } catch (e) {
            this._socket.emit('requestError', e instanceof Error ? e : new Error(String(e)));
            return;
        }

        // Skip responses — the multicast group sees plenty of those
        // from other devices and from our own outgoing replies.
        if (parsed.header.qr === 1) {
            return;
        }

        const send = this._buildSend(parsed, rinfo);
        this._socket.emit('request', parsed, send, rinfo, data);
    }

    /**
     * Build the per-request response callback. Resolves the multicast
     * vs unicast decision lazily so the handler can override `target`.
     * @param {Packet} request
     * @param {dgram.RemoteInfo} rinfo
     * @return {(msg: MdnsSendable, target?: MdnsResponseTarget) => Promise<void>}
     * @protected
     */
    protected _buildSend(
        request: Packet,
        rinfo: dgram.RemoteInfo
    ): (msg: MdnsSendable, target?: MdnsResponseTarget) => Promise<void> {
        return (msg: MdnsSendable, target: MdnsResponseTarget = 'auto'): Promise<void> => {
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
                    } else {
                        resolve();
                    }
                });
            });
        };
    }

    /**
     * Whether any question on `packet` carried the QU bit (top bit of
     * QCLASS — RFC 6762 §5.4). A single QU question flips the whole
     * response to unicast under `target: 'auto'`.
     * @param {Packet} packet
     * @return {boolean}
     * @protected
     */
    protected static _anyQuestionHasQu(packet: Packet): boolean {
        for (const q of packet.questions) {
            // eslint-disable-next-line no-bitwise
            if ((q.class & MDNS_QU_BIT) !== 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether `addr` is in the IPv4 (224.0.0.0/4) or IPv6 (ff00::/8)
     * multicast range. Mirrors the helper in `MdnsClient`.
     * @param {string} addr
     * @return {boolean}
     * @protected
     */
    protected static _isMulticast(addr: string): boolean {
        if (addr.includes(':')) {
            return addr.toLowerCase().startsWith('ff');
        }

        const firstOctet = Number.parseInt(addr.split('.')[0], 10);
        return firstOctet >= 224 && firstOctet <= 239;
    }

}