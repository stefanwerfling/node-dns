import fs from 'fs';
import { HostsFile } from '../Lib/HostsFile.js';
import { ResolvConf } from '../Lib/ResolvConf.js';
import { UDPClient } from '../Client/UDPClient.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { FailoverBackend } from './FailoverBackend.js';
import { StubResolver } from './StubResolver.js';
const DEFAULT_NAMESERVER_PORT = 53;
const defaultBackend = ({ host, port }) => UDPClient.request({
    dns: host,
    port: port ?? DEFAULT_NAMESERVER_PORT
});
export class SystemResolver {
    _stub;
    constructor(stub) {
        this._stub = stub;
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
            shouldFailover: options.shouldFailover
        });
    }
    static fromConfig(conf, options = {}) {
        const failover = FailoverBackend.fromConfig(conf, options.backend ?? defaultBackend, {
            shouldFailover: options.shouldFailover
        });
        if (failover === null) {
            throw new Error('SystemResolver: resolv.conf carries no `nameserver` entries');
        }
        const backend = options.hostsFile !== undefined
            ? options.hostsFile.asResolverBackend(failover)
            : failover;
        const stub = StubResolver.fromConfig(conf, backend);
        return new SystemResolver(stub);
    }
    resolve(name, type, cls = PacketClass.IN) {
        return this._stub.resolve(name, type, cls);
    }
    get stub() {
        return this._stub;
    }
    static hasSystemFiles(options = {}) {
        return {
            resolvConf: fs.existsSync(options.resolvConfPath ?? ResolvConf.DEFAULT_PATH),
            hosts: fs.existsSync(options.hostsPath ?? HostsFile.DEFAULT_PATH)
        };
    }
}
//# sourceMappingURL=SystemResolver.js.map