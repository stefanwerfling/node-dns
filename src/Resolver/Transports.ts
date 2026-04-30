import dgram from 'dgram';
import tcp from 'net';
import {SocketReader} from '../Lib/SocketReader.js';
import {Packet} from '../Packet/Packet.js';
import type {RecursiveResolverTransport} from './RecursiveResolver.js';

/**
 * Default transports for `RecursiveResolver`. Both follow the
 * `RecursiveResolverTransport` contract: send `query` to
 * `serverIp:port`, wait for a single response, return the parsed
 * `Packet`. No connection reuse in v1 — every query opens a fresh
 * socket. Tests override these via the resolver's `transport` /
 * `tcpTransport` options to drive deterministic referral chains.
 */

/**
 * Default UDP transport. One-shot dgram socket per query — no
 * connection pooling. Picks `udp4` / `udp6` based on whether
 * `serverIp` is colon-bearing (a quick proxy for IPv6 detection that
 * matches what Node's resolver does internally).
 */
export const defaultUdpTransport: RecursiveResolverTransport = (
    serverIp: string,
    port: number,
    query: Packet
): Promise<Packet> => {
    return new Promise((resolve, reject) => {
        const family = serverIp.includes(':') ? 'udp6' : 'udp4';
        const socket = dgram.createSocket(family);
        let settled = false;

        const finish = (err: Error | null, packet?: Packet): void => {
            if (settled) {
                return;
            }

            settled = true;

            try {
                socket.close();
            } catch {
                /* socket may already be closed */
            }

            if (err) {
                reject(err);
            } else {
                resolve(packet!);
            }
        };

        socket.once('message', (msg) => {
            try {
                finish(null, Packet.parse(msg));
            } catch (err) {
                finish(err instanceof Error ? err : new Error(String(err)));
            }
        });

        socket.once('error', (err) => finish(err));

        socket.send(query.toBuffer(), port, serverIp, (err) => {
            if (err) {
                finish(err);
            }
        });
    });
};

/**
 * Default TCP transport for the TC=1 retry path (RFC 7766 §5).
 * One-shot length-prefixed connection per query — no connection
 * pooling in v1. Reuses `SocketReader.readStream` for the same
 * length-prefix framing every other TCP DNS path uses.
 */
export const defaultTcpTransport: RecursiveResolverTransport = (
    serverIp: string,
    port: number,
    query: Packet
): Promise<Packet> => {
    return new Promise((resolve, reject) => {
        const socket = tcp.createConnection({host: serverIp, port: port});
        let settled = false;

        const finish = (err: Error | null, packet?: Packet): void => {
            if (settled) {
                return;
            }

            settled = true;

            try {
                socket.destroy();
            } catch {
                /* socket may already be closed */
            }

            if (err) {
                reject(err);
            } else {
                resolve(packet!);
            }
        };

        socket.once('connect', () => {
            const message = query.toBuffer();
            const len = Buffer.alloc(2);
            len.writeUInt16BE(message.length);
            socket.write(Buffer.concat([len, message]));
        });

        SocketReader.readStream(socket).then(
            (data) => {
                try {
                    finish(null, Packet.parse(data));
                } catch (err) {
                    finish(err instanceof Error ? err : new Error(String(err)));
                }
            },
            (err) => finish(err)
        );
    });
};