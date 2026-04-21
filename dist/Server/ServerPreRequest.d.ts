import { Buffer } from 'buffer';
export type ServerPreRequestResult<TClient> = {
    data: Buffer;
    client?: TClient;
};
export interface ServerPreRequest<TClient = unknown> {
    process(data: Buffer, client: TClient): Promise<ServerPreRequestResult<TClient>>;
}
