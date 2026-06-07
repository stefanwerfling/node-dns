import tls from 'tls';
import { CookieGuard } from './CookieGuard.js';
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
            if (opt.cookies) {
                this._cookies = new CookieGuard(opt.cookies);
            }
        }
    }
    _createInternalServer(listener) {
        const tlsOptions = this._options.tls.options;
        return tls.createServer(tlsOptions, listener);
    }
}
//# sourceMappingURL=TLSServer.js.map