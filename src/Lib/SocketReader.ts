import { Buffer } from 'buffer';
import tcp from 'net';

/**
 * Socket Reader
 */
export class SocketReader {

    /**
     * Read the socket stream (handle chunks) to Buffer
     * @param {tcp.Socket} socket
     * @return {Promise<Buffer>}
     */
    public static readStream(socket: tcp.Socket): Promise<Buffer> {
        let chunks: Buffer[] = [];
        let chunklen = 0;
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

            socket.on('error', reject);
            socket.on('end', processMessage);
            socket.on('readable', () => {
                let chunk;

                while ((chunk = socket.read()) !== null) {
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }

                if (!expected && chunklen >= 2) {
                    if (chunks.length > 1) {
                        chunks = [Buffer.concat(chunks, chunklen)];
                    }

                    expected = chunks[0].readUInt16BE(0);
                }

                if (expected !== null && chunklen >= 2 + expected) {
                    processMessage();
                }
            });
        });
    }

}