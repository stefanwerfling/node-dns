import tcp from 'net';
import tls from 'tls';
import {ServerOptions} from './ServerOptions.js';
import {ServerPreConnection} from './ServerPreConnection.js';
import {ServerPreRequest} from './ServerPreRequest.js';
import {TCPServer} from './TCPServer.js';

/**
 * DNS over TLS server (RFC 7858).
 *
 * Reuses the TCPServer length-prefixed framing, hooks and handler logic; only
 * the underlying transport server is swapped from `net.createServer` to
 * `tls.createServer`. TLS context (cert, key, ca, ...) is supplied via
 * `ServerOptions.tls.options`.
 */
export class TLSServer extends TCPServer {

    /**
     * Constructor
     * @param {ServerOptions|null} options
     */
    public constructor(options: ServerOptions|null = null) {
        if (!options || !options.tls || !options.tls.options) {
            throw new Error('TLSServer requires options.tls.options with TLS context (cert/key)');
        }

        super(options);
    }

    /**
     * Read TLS-specific hook options.
     * @protected
     */
    protected override _loadHooks(): void {
        const opt = this._options?.tls;

        if (opt) {
            if (opt.preRequest) {
                this._preRequest = opt.preRequest as ServerPreRequest<tcp.Socket>;
            }

            if (opt.preConnection) {
                this._preConnection = opt.preConnection as ServerPreConnection<tcp.Socket>;
            }
        }
    }

    /**
     * Create a `tls.Server` instead of a plain `net.Server`. The connection
     * listener receives `tls.TLSSocket`, which extends `net.Socket`, so the
     * inherited `_handle`/`_response` flow works unchanged.
     * @param {(socket: tcp.Socket) => void} listener
     * @return {tls.Server}
     * @protected
     */
    protected override _createInternalServer(listener: (socket: tcp.Socket) => void): tls.Server {
        // Constructor pre-check guarantees these exist.
        const tlsOptions = this._options!.tls!.options;

        return tls.createServer(tlsOptions, listener);
    }

}