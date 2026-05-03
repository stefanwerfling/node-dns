import type { ParsedResolvConf } from '../Lib/ResolvConf.js';
import { Packet } from '../Packet/Packet.js';
import type { StubResolverBackend } from './StubResolver.js';
export type FailoverPredicate = (resultOrError: Packet | Error) => boolean;
export type FailoverOptions = {
    timeoutMs?: number;
    attempts?: number;
    rotate?: boolean;
    shouldFailover?: FailoverPredicate;
};
export type FailoverBackendBuilder = (target: {
    host: string;
    port?: number;
}) => StubResolverBackend;
export declare class FailoverBackend {
    static combine(backends: StubResolverBackend[], options?: FailoverOptions): StubResolverBackend;
    static fromConfig(parsed: ParsedResolvConf, builder: FailoverBackendBuilder, options?: Pick<FailoverOptions, 'shouldFailover'>): StubResolverBackend | null;
    static readonly defaultShouldFailover: FailoverPredicate;
}
