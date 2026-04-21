import { Buffer } from 'buffer';
export type ServerPreConnectionResult<TClient> = {
    client?: TClient;
    initialBuffer?: Buffer;
};
export interface ServerPreConnection<TClient = unknown> {
    process(client: TClient): Promise<ServerPreConnectionResult<TClient>>;
}
