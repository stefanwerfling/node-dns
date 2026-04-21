import { Buffer } from 'buffer';
import tcp from 'net';

/**
 * Socket Reader
 */
export class SocketReader {

    /**
     * Read the socket stream (handle chunks) to Buffer.
     *
     * If `initialBuffer` is provided, its bytes are treated as if they had
     * already been received from the socket — useful when a preamble (e.g.
     * PROXY header) has been consumed earlier and the remaining pre-read
     * bytes need to be fed into the DNS length-prefix framing.
     * @param {tcp.Socket} socket
     * @param {[Buffer]} initialBuffer
     * @return {Promise<Buffer>}
     */
    public static readStream(socket: tcp.Socket, initialBuffer?: Buffer): Promise<Buffer> {
        let chunks: Buffer[] = initialBuffer && initialBuffer.length > 0 ? [initialBuffer] : [];
        let chunklen = initialBuffer ? initialBuffer.length : 0;
        let received = false;
        let expected: number|null = null;

        return new Promise<Buffer>((resolve, reject) => {
            const processMessage = (): void => {
                if (received) {
                    return;
                }

                received = true;

                const buffer = Buffer.concat(chunks, chunklen);
                resolve(buffer.subarray(2));
            };

            const tryResolve = (): void => {
                if (!expected && chunklen >= 2) {
                    if (chunks.length > 1) {
                        chunks = [Buffer.concat(chunks, chunklen)];
                    }

                    expected = chunks[0].readUInt16BE(0);
                }

                if (expected !== null && chunklen >= 2 + expected) {
                    processMessage();
                }
            };

            socket.on('error', reject);
            socket.on('end', processMessage);
            socket.on('readable', () => {
                let chunk;

                while ((chunk = socket.read()) !== null) {
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }

                tryResolve();
            });

            // Evaluate any preloaded initial buffer immediately.
            if (chunklen > 0) {
                tryResolve();
            }
        });
    }

}