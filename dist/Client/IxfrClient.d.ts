import { Buffer } from 'buffer';
import tcp from 'net';
import tls from 'tls';
import { PacketResource } from '../Packet/PacketResource.js';
import { SOA } from '../Packet/Types/SOA.js';
import { AClient } from './AClient.js';
import { ClientOptionsProtocol } from './ClientOptions.js';
export type IxfrClientOptions = {
    dns: string;
    port?: number;
    protocol?: ClientOptionsProtocol.tcp | ClientOptionsProtocol.tls;
};
export type IxfrChangeSet = {
    fromSerial: number;
    toSerial: number;
    deletions: PacketResource[];
    additions: PacketResource[];
};
export type IxfrResult = {
    type: 'noChange';
    soa: PacketResource;
} | {
    type: 'incremental';
    currentSoa: PacketResource;
    diffs: IxfrChangeSet[];
} | {
    type: 'fullAxfr';
    soa: PacketResource;
    records: PacketResource[];
};
export declare class IxfrClient extends AClient {
    static makeQuery(zoneName: string, currentSoa: SOA): Buffer;
    static connect(option: IxfrClientOptions): tcp.Socket | tls.TLSSocket;
    static request(option: IxfrClientOptions): (zoneName: string, currentSoa: SOA) => Promise<IxfrResult>;
    protected static _classify(answers: PacketResource[]): IxfrResult;
}
