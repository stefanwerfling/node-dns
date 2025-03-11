import { AClient } from './AClient.js';
import { ClientOptions } from './ClientOptions.js';
import { ClientRequest } from './ClientRequest.js';
export type ClientCreateResolver = {
    new (): AClient;
    request(option: ClientOptions): ClientRequest;
};
