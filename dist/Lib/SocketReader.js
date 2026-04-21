import { Buffer } from 'buffer';
export class SocketReader {
    static readStream(socket, initialBuffer) {
        let chunks = initialBuffer && initialBuffer.length > 0 ? [initialBuffer] : [];
        let chunklen = initialBuffer ? initialBuffer.length : 0;
        let received = false;
        let expected = null;
        return new Promise((resolve, reject) => {
            const processMessage = () => {
                if (received) {
                    return;
                }
                received = true;
                const buffer = Buffer.concat(chunks, chunklen);
                resolve(buffer.subarray(2));
            };
            const tryResolve = () => {
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
            if (chunklen > 0) {
                tryResolve();
            }
        });
    }
}
//# sourceMappingURL=SocketReader.js.map