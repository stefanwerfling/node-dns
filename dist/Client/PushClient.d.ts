import { Buffer } from 'buffer';
import { EventEmitter } from 'events';
import tls from 'tls';
import { DsoMessage, PushTlv } from '../Lib/Dso.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
export type PushClientOptions = {
    host: string;
    port?: number;
    tls?: tls.ConnectionOptions;
    requestTimeoutMs?: number;
    inactivityMs?: number;
    keepaliveMs?: number;
};
export declare class PushSubscription extends EventEmitter {
    readonly name: string;
    readonly qtype: number;
    readonly qclass: number;
    readonly messageId: number;
    _active: boolean;
    protected _client: PushClient;
    constructor(client: PushClient, name: string, qtype: number, qclass: number, messageId: number);
    unsubscribe(): Promise<void>;
}
type PendingRequest = {
    resolve: (msg: DsoMessage) => void;
    reject: (err: Error) => void;
    timer: NodeJS.Timeout;
};
export declare class PushClient extends EventEmitter {
    protected _options: Required<Omit<PushClientOptions, 'tls'>> & {
        tls: tls.ConnectionOptions;
    };
    protected _socket: tls.TLSSocket | null;
    protected _ready: Promise<void> | null;
    protected _readBuffer: Buffer;
    protected _expected: number | null;
    protected _nextMessageId: number;
    protected _pending: Map<number, PendingRequest>;
    protected _subscriptions: Map<number, PushSubscription>;
    protected _closed: boolean;
    constructor(options: PushClientOptions);
    subscribe(name: string, qtype: PacketTypes | number, qclass?: PacketClass | number): Promise<PushSubscription>;
    close(): Promise<void>;
    get subscriptionCount(): number;
    _unsubscribe(sub: PushSubscription): Promise<void>;
    protected _ensureConnected(): Promise<void>;
    protected _sendMessage(message: DsoMessage): void;
    protected _drainFrames(): void;
    protected _handleFrame(frame: Buffer): void;
    protected _dispatchPush(tlv: PushTlv): void;
    protected static _matches(sub: PushSubscription, record: PacketResource): boolean;
    protected _allocateMessageId(): number;
    protected _awaitResponse(messageId: number): Promise<DsoMessage>;
    protected _teardown(err: Error): void;
}
export {};
