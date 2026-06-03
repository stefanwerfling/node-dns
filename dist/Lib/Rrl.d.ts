import { Buffer } from 'buffer';
export type RrlDecision = 'allow' | 'drop' | 'truncate';
export type RrlOptions = {
    maxRate: number;
    capacity?: number;
    prefixV4Bits?: number;
    prefixV6Bits?: number;
    slipRatio?: number;
    maxBuckets?: number;
};
type Bucket = {
    tokens: number;
    last: number;
    drops: number;
};
export declare class Rrl {
    readonly maxRate: number;
    readonly capacity: number;
    readonly prefixV4Bits: number;
    readonly prefixV6Bits: number;
    readonly slipRatio: number;
    readonly maxBuckets: number;
    protected readonly _buckets: Map<string, Bucket>;
    constructor(options: RrlOptions);
    check(clientIp: string, qtype: number, now?: number): RrlDecision;
    size(): number;
    reset(): void;
    protected _prefixKey(ip: string): string;
    protected static _maskInPlace(buf: Buffer, prefixBits: number): void;
}
export {};
