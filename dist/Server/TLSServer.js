import tls from 'tls';
import { TCPServer } from './TCPServer.js';
export class TLSServer extends TCPServer {
    constructor(options = null) {
        if (!options || !options.tls || !options.tls.options) {
            throw new Error('TLSServer requires options.tls.options with TLS context (cert/key)');
        }
        super(options);
    }
    _loadHooks() {
        const opt = this._options?.tls;
        if (opt) {
            if (opt.preRequest) {
                this._preRequest = opt.preRequest;
            }
            if (opt.preConnection) {
                this._preConnection = opt.preConnection;
            }
        }
    }
    _createInternalServer(listener) {
        const tlsOptions = this._options.tls.options;
        return tls.createServer(tlsOptions, listener);
    }
}
//# sourceMappingURL=TLSServer.js.map