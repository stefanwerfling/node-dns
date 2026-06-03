import { Buffer } from 'buffer';
import { EventEmitter } from 'events';
import net from 'net';
import tls from 'tls';
import { DsoMessage, KeepaliveTlv, SubscribeTlv, UnsubscribeTlv } from '../Lib/Dso.js';
import { PacketResource } from '../Packet/PacketResource.js';
export type PushServerOptions = {
    tls: tls.TlsOptions;
    inactivityMs?: number;
    keepaliveMs?: number;
};
type ServerSubscription = {
    name: string;
    qtype: number;
    qclass: number;
    messageId: number;
};
declare class PushSession extends EventEmitter {
    readonly socket: tls.TLSSocket;
    readonly subscriptions: Map<number, ServerSubscription>;
    protected _readBuffer: Buffer;
    protected _expected: number | null;
    protected _server: PushServer;
    protected _closed: boolean;
    constructor(server: PushServer, socket: tls.TLSSocket);
    sendMessage(message: DsoMessage): void;
    sendRetryDelay(retryDelayMs: number, closeAfter?: boolean): void;
    close(): void;
    get closed(): boolean;
    protected _drainFrames(): void;
    protected _handleFrame(frame: Buffer): void;
    protected _handleSubscribe(messageId: number, tlv: SubscribeTlv): void;
    protected _handleUnsubscribe(tlv: UnsubscribeTlv): void;
    protected _handleKeepalive(messageId: number, tlv: KeepaliveTlv): void;
    protected _teardown(err?: Error): void;
}
export declare class PushServer extends EventEmitter {
    readonly inactivityMs: number;
    readonly keepaliveMs: number;
    protected _options: PushServerOptions;
    protected _server: tls.Server | null;
    protected _sessions: Set<PushSession>;
    protected _index: Map<string, Set<PushSession>>;
    constructor(options: PushServerOptions);
    listen(port?: number, host?: string): Promise<void>;
    address(): net.AddressInfo | null;
    notify(records: PacketResource[]): number;
    close(): Promise<void>;
    get sessionCount(): number;
    _registerSubscription(_session: PushSession): void;
    _unregisterSession(session: PushSession): void;
    protected static _normalize(name: string): string;
}
export type { PushSession };
