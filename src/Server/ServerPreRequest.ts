import {Buffer} from 'buffer';

/**
 * Result returned by a ServerPreRequest processor
 */
export type ServerPreRequestResult<TClient> = {
    /**
     * The (possibly modified) raw DNS packet buffer that will be parsed by the server.
     */
    data: Buffer;

    /**
     * Optional overridden client information. When provided, this value is emitted
     * to the `request` event listeners instead of the original client (e.g. the
     * original remote-info with the real client IP after stripping a PROXY header).
     */
    client?: TClient;
};

/**
 * Processor that inspects/modifies the raw packet data (and optionally the client
 * information) before the server parses the DNS packet.
 *
 * Use cases: stripping a PROXY protocol header and injecting the original client
 * address, rewriting transport wrappers, metrics, etc.
 */
export interface ServerPreRequest<TClient = unknown> {

    /**
     * Process the incoming raw buffer.
     * @param {Buffer} data raw packet data as received on the transport
     * @param {TClient} client transport-specific client information
     * @return {Promise<ServerPreRequestResult<TClient>>}
     */
    process(data: Buffer, client: TClient): Promise<ServerPreRequestResult<TClient>>;

}