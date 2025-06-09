import { Buffer } from 'buffer';
import tcp from 'net';
export declare class SocketReader {
    static readStream(socket: tcp.Socket): Promise<Buffer>;
}
