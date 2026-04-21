import { AClient } from './AClient.js';
export type GoogleDnsResponse = {
    Status: number;
    TC: boolean;
    RD: boolean;
    RA: boolean;
    AD: boolean;
    CD: boolean;
    Question: {
        name: string;
        type: number;
    }[];
    Answer?: {
        name: string;
        type: number;
        TTL: number;
        data: string;
    }[];
    Authority?: {
        name: string;
        type: number;
        TTL: number;
        data: string;
    }[];
};
export type GoogleClientRequest = (name: string, type?: string) => Promise<GoogleDnsResponse>;
export declare class GoogleClient extends AClient {
    private static _get;
    private static _readStream;
    static request(): GoogleClientRequest;
}
