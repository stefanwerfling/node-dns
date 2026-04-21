import {Buffer} from 'buffer';

/**
 * Result returned by a ServerPreConnection processor.
 */
export type ServerPreConnectionResult<TClient> = {
    /**
     * Optional overridden client reference emitted with `request` events
     * instead of the original (e.g. a socket with overridden remoteAddress/
     * remotePort after a PROXY protocol header has been stripped).
     */
    client?: TClient;

    /**
     * Any bytes that were already read from the underlying stream but do not
     * belong to the connection prelude. They will be treated by the server as
     * the first bytes of the actual protocol stream (prepended before further
     * reads).
     */
    initialBuffer?: Buffer;
};

/**
 * Processor that runs once when a new connection is accepted, before any
 * protocol data is parsed. Typical use: consume a PROXY protocol header
 * from the stream and expose the original client endpoint.
 */
export interface ServerPreConnection<TClient = unknown> {

    /**
     * Handle a freshly accepted connection / client.
     * @param {TClient} client
     * @return {Promise<ServerPreConnectionResult<TClient>>}
     */
    process(client: TClient): Promise<ServerPreConnectionResult<TClient>>;

}