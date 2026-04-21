import https from 'https';
import { AClient } from './AClient.js';
export class GoogleClient extends AClient {
    static _get(url) {
        return new Promise((resolve) => {
            https.get(url, resolve);
        });
    }
    static _readStream(stream) {
        const bufferChunks = [];
        return new Promise((resolve, reject) => {
            stream
                .on('error', reject)
                .on('data', (chunk) => {
                bufferChunks.push(chunk);
            })
                .on('end', () => resolve(Buffer.concat(bufferChunks)));
        });
    }
    static request() {
        return (name, type = 'ANY') => {
            return GoogleClient._get(`https://dns.google.com/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`)
                .then(GoogleClient._readStream)
                .then((buffer) => JSON.parse(buffer.toString()));
        };
    }
}
//# sourceMappingURL=GoogleClient.js.map