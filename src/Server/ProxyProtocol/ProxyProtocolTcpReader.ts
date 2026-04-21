import {Buffer} from 'buffer';
import tcp from 'net';

/**
 * Function that inspects the accumulated buffer and returns the number of
 * bytes the PROXY header occupies. Returns null if more bytes are required,
 * throws on protocol errors.
 */
export type ProxyProtocolBytesNeeded = (data: Buffer) => number|null;

/**
 * Result of reading a PROXY header from a socket.
 */
export type ProxyProtocolSocketReadResult = {
    /**
     * Bytes that represent the PROXY header itself.
     */
    header: Buffer;

    /**
     * Any bytes that were already read from the socket beyond the header
     * and therefore belong to the following protocol payload.
     */
    remainder: Buffer;
};

/**
 * Helper that consumes exactly the PROXY header bytes from a socket, leaving
 * any excess bytes available to a subsequent reader via the returned
 * `remainder` buffer. The caller is responsible for feeding that buffer into
 * whatever reader continues with the connection.
 */
export class ProxyProtocolTcpReader {

    /**
     * Read bytes from `socket` until `bytesNeeded` signals the PROXY header
     * is complete, then detach all installed listeners and resolve with the
     * split header / remainder buffers.
     * @param {tcp.Socket} socket
     * @param {ProxyProtocolBytesNeeded} bytesNeeded
     * @return {Promise<ProxyProtocolSocketReadResult>}
     */
    public static readHeader(
        socket: tcp.Socket,
        bytesNeeded: ProxyProtocolBytesNeeded
    ): Promise<ProxyProtocolSocketReadResult> {
        return new Promise((resolve, reject) => {
            const state: {
                chunks: Buffer[];
                total: number;
                needed: number|null;
                finished: boolean;
            } = {
                chunks: [],
                total: 0,
                needed: null,
                finished: false
            };

            const drain = (): void => {
                let chunk: Buffer|null;

                while ((chunk = socket.read() as Buffer|null) !== null) {
                    state.chunks.push(chunk);
                    state.total += chunk.length;
                }
            };

            const merge = (): Buffer => {
                if (state.chunks.length === 1) {
                    return state.chunks[0];
                }

                const merged = Buffer.concat(state.chunks, state.total);
                state.chunks = [merged];
                return merged;
            };

            const tryResult = (): ProxyProtocolSocketReadResult|null => {
                if (state.needed === null) {
                    state.needed = bytesNeeded(merge());
                }

                if (state.needed !== null && state.total >= state.needed) {
                    const merged = merge();

                    return {
                        header: merged.subarray(0, state.needed),
                        remainder: merged.subarray(state.needed)
                    };
                }

                return null;
            };

            const listeners: {
                onReadable: () => void;
                onError: (err: Error) => void;
                onEnd: () => void;
            } = {
                onReadable: (): void => {
                    // noop placeholder, replaced below
                },
                onError: (): void => {
                    // noop placeholder, replaced below
                },
                onEnd: (): void => {
                    // noop placeholder, replaced below
                }
            };

            const detach = (): void => {
                socket.off('readable', listeners.onReadable);
                socket.off('error', listeners.onError);
                socket.off('end', listeners.onEnd);
            };

            const settleOk = (result: ProxyProtocolSocketReadResult): void => {
                if (state.finished) {
                    return;
                }

                state.finished = true;
                detach();
                resolve(result);
            };

            const settleErr = (err: unknown): void => {
                if (state.finished) {
                    return;
                }

                state.finished = true;
                detach();
                reject(err instanceof Error ? err : new Error(String(err)));
            };

            listeners.onReadable = (): void => {
                drain();

                try {
                    const result = tryResult();

                    if (result) {
                        settleOk(result);
                    }
                } catch (err) {
                    settleErr(err);
                }
            };

            listeners.onError = (err: Error): void => {
                settleErr(err);
            };

            listeners.onEnd = (): void => {
                settleErr(new Error('PROXY: socket closed before header was complete'));
            };

            socket.on('readable', listeners.onReadable);
            socket.on('error', listeners.onError);
            socket.on('end', listeners.onEnd);

            // In case bytes are already buffered, prime the pump.
            listeners.onReadable();
        });
    }

}