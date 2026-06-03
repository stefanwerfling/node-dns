import { Buffer } from 'buffer';
export declare class IpBytes {
    static parseIPv4(ip: string): Buffer;
    static parseIPv6(ip: string): Buffer;
    static parse(ip: string): Buffer;
}
