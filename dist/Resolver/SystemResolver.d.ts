import { HostsFile } from '../Lib/HostsFile.js';
import { ParsedResolvConf } from '../Lib/ResolvConf.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { DnsCache, DnsCacheOptions } from './DnsCache.js';
import { FailoverBackendBuilder, FailoverPredicate } from './FailoverBackend.js';
import { StubResolver } from './StubResolver.js';
export type SystemResolverCache = boolean | DnsCache | DnsCacheOptions;
export type SystemResolverOptions = {
    resolvConfPath?: string;
    hostsPath?: string;
    skipHosts?: boolean;
    backend?: FailoverBackendBuilder;
    shouldFailover?: FailoverPredicate;
    cache?: SystemResolverCache;
};
export declare class SystemResolver {
    protected _stub: StubResolver;
    protected _cache: DnsCache | null;
    constructor(stub: StubResolver, cache?: DnsCache | null);
    static system(options?: SystemResolverOptions): SystemResolver;
    static fromConfig(conf: ParsedResolvConf, options?: {
        hostsFile?: HostsFile;
        backend?: FailoverBackendBuilder;
        shouldFailover?: FailoverPredicate;
        cache?: SystemResolverCache;
    }): SystemResolver;
    protected static _resolveCacheOption(option: SystemResolverCache | undefined): DnsCache | null;
    resolve(name: string, type: PacketTypes | number, cls?: PacketClass | number): Promise<Packet>;
    get stub(): StubResolver;
    get cache(): DnsCache | null;
    static hasSystemFiles(options?: Pick<SystemResolverOptions, 'resolvConfPath' | 'hostsPath'>): {
        resolvConf: boolean;
        hosts: boolean;
    };
}
