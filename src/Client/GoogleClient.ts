import http from 'http';
import https from 'https';
import {AClient} from './AClient.js';

/**
 * Google DNS JSON response
 */
export type GoogleDnsResponse = {
    Status: number;
    TC: boolean;
    RD: boolean;
    RA: boolean;
    AD: boolean;
    CD: boolean;
    Question: {name: string; type: number;}[];
    Answer?: {name: string; type: number; TTL: number; data: string;}[];
    Authority?: {name: string; type: number; TTL: number; data: string;}[];
};

/**
 * Google DNS Client request function
 */
export type GoogleClientRequest = (name: string, type?: string) => Promise<GoogleDnsResponse>;

/**
 * GoogleClient - Uses Google DNS JSON API
 * @docs https://developers.google.com/speed/public-dns/docs/doh/json
 */
export class GoogleClient extends AClient {

    /**
     * HTTP GET helper
     * @param {string} url
     * @return {Promise<http.IncomingMessage>}
     */
    private static _get(url: string): Promise<http.IncomingMessage> {
        return new Promise((resolve) => {
            https.get(url, resolve);
        });
    }

    /**
     * Read a stream to Buffer
     * @param {http.IncomingMessage} stream
     * @return {Promise<Buffer>}
     */
    private static _readStream(stream: http.IncomingMessage): Promise<Buffer> {
        const bufferChunks: Buffer[] = [];

        return new Promise((resolve, reject) => {
            stream
            .on('error', reject)
            .on('data', (chunk: Buffer) => {
                bufferChunks.push(chunk);
            })
            .on('end', () => resolve(Buffer.concat(bufferChunks)));
        });
    }

    /**
     * Create a Google DNS resolver function
     * @return {GoogleClientRequest}
     */
    public static request(): GoogleClientRequest {
        return (name: string, type: string = 'ANY'): Promise<GoogleDnsResponse> => {
            return GoogleClient._get(
                `https://dns.google.com/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`
            )
            .then(GoogleClient._readStream)
            .then((buffer) => JSON.parse(buffer.toString()) as GoogleDnsResponse);
        };
    }

}