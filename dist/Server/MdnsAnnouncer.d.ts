import { PacketResource } from '../Packet/PacketResource.js';
import { MdnsServer } from './MdnsServer.js';
export type MdnsAnnouncerOptions = {
    schedule?: number[];
    steadyStateMs?: number;
    goodbyeOnStop?: boolean;
    initialAnnounce?: boolean;
};
export declare class MdnsAnnouncer {
    protected _server: MdnsServer;
    protected _records: PacketResource[];
    protected _schedule: number[];
    protected _steadyStateMs: number;
    protected _goodbyeOnStop: boolean;
    protected _initialAnnounce: boolean;
    protected _timer: NodeJS.Timeout | null;
    protected _stepIndex: number;
    protected _running: boolean;
    protected _onError: ((err: Error) => void) | null;
    constructor(server: MdnsServer, records: PacketResource[], options?: MdnsAnnouncerOptions);
    start(): this;
    stop(): Promise<void>;
    on(event: 'error', listener: (err: Error) => void): this;
    get running(): boolean;
    protected _scheduleNext(): void;
    protected _announce(): void;
    protected _reportError(err: unknown): void;
}
