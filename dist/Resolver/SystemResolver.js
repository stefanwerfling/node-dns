import fs from 'fs';
import { HostsFile } from '../Lib/HostsFile.js';
import { ResolvConf } from '../Lib/ResolvConf.js';
import { UDPClient } from '../Client/UDPClient.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { CachedStubBackend } from './CachedStubBackend.js';
import { DnsCache } from './DnsCache.js';
import { FailoverBackend } from './FailoverBackend.js';
import { StubResolver } from './StubResolver.js';
const DEFAULT_NAMESERVER_PORT = 53;
const defaultBackend = ({ host, port }) => UDPClient.request({
    dns: host,
    port: port ?? DEFAULT_NAMESERVER_PORT
});
export class SystemResolver {
    _stub;
    _cache;
    _hostsWatch;
    constructor(stub, cache = null, hostsWatch = null) {
        this._stub = stub;
        this._cache = cache;
        this._hostsWatch = hostsWatch;
    }
    static system(options = {}) {
        const conf = ResolvConf.fromFile(options.resolvConfPath ?? ResolvConf.DEFAULT_PATH);
        let hosts = null;
        if (options.skipHosts !== true) {
            const hostsPath = options.hostsPath ?? HostsFile.DEFAULT_PATH;
            try {
                hosts = HostsFile.fromFile(hostsPath);
            }
            catch (err) {
                const e = err;
                if (e.code !== 'ENOENT' && e.code !== 'EACCES' && e.code !== 'EPERM') {
                    throw err;
                }
            }
        }
        return SystemResolver.fromConfig(conf, {
            hostsFile: hosts ?? undefined,
            backend: options.backend,
            shouldFailover: options.shouldFailover,
            cache: options.cache,
            watchHosts: options.watchHosts
        });
    }
    static fromConfig(conf, options = {}) {
        const failover = FailoverBackend.fromConfig(conf, options.backend ?? defaultBackend, {
            shouldFailover: options.shouldFailover
        });
        if (failover === null) {
            throw new Error('SystemResolver: resolv.conf carries no `nameserver` entries');
        }
        const cacheInstance = SystemResolver._resolveCacheOption(options.cache);
        const cachedUpstream = cacheInstance !== null
            ? new CachedStubBackend(failover, { cache: cacheInstance }).resolve
            : failover;
        const backend = options.hostsFile !== undefined
            ? options.hostsFile.asResolverBackend(cachedUpstream)
            : cachedUpstream;
        const stub = StubResolver.fromConfig(conf, backend);
        let hostsWatch = null;
        if (options.watchHosts !== undefined && options.watchHosts !== false && options.hostsFile !== undefined) {
            const watchOpts = options.watchHosts === true
                ? {}
                : options.watchHosts;
            hostsWatch = options.hostsFile.watch(watchOpts);
        }
        return new SystemResolver(stub, cacheInstance, hostsWatch);
    }
    static _resolveCacheOption(option) {
        if (option === undefined || option === false) {
            return null;
        }
        if (option === true) {
            return new DnsCache();
        }
        if (option instanceof DnsCache) {
            return option;
        }
        return new DnsCache(option);
    }
    resolve(name, type, cls = PacketClass.IN) {
        return this._stub.resolve(name, type, cls);
    }
    get stub() {
        return this._stub;
    }
    get cache() {
        return this._cache;
    }
    get hostsWatch() {
        return this._hostsWatch;
    }
    close() {
        if (this._hostsWatch !== null) {
            this._hostsWatch.close();
        }
    }
    static hasSystemFiles(options = {}) {
        return {
            resolvConf: fs.existsSync(options.resolvConfPath ?? ResolvConf.DEFAULT_PATH),
            hosts: fs.existsSync(options.hostsPath ?? HostsFile.DEFAULT_PATH)
        };
    }
}
//# sourceMappingURL=SystemResolver.js.map