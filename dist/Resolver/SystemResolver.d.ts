import { HostsFile } from '../Lib/HostsFile.js';
import { ParsedResolvConf } from '../Lib/ResolvConf.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { FailoverBackendBuilder, FailoverPredicate } from './FailoverBackend.js';
import { StubResolver } from './StubResolver.js';
export type SystemResolverOptions = {
    resolvConfPath?: string;
    hostsPath?: string;
    skipHosts?: boolean;
    backend?: FailoverBackendBuilder;
    shouldFailover?: FailoverPredicate;
};
export declare class SystemResolver {
    protected _stub: StubResolver;
    constructor(stub: StubResolver);
    static system(options?: SystemResolverOptions): SystemResolver;
    static fromConfig(conf: ParsedResolvConf, options?: {
        hostsFile?: HostsFile;
        backend?: FailoverBackendBuilder;
        shouldFailover?: FailoverPredicate;
    }): SystemResolver;
    resolve(name: string, type: PacketTypes | number, cls?: PacketClass | number): Promise<Packet>;
    get stub(): StubResolver;
    static hasSystemFiles(options?: Pick<SystemResolverOptions, 'resolvConfPath' | 'hostsPath'>): {
        resolvConf: boolean;
        hosts: boolean;
    };
}
