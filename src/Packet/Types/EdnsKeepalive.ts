import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {EdnsOption, EdnsOptionCode} from './EdnsECS.js';

/**
 * EDNS(0) edns-tcp-keepalive option (RFC 7828).
 *
 * Client sends with empty payload (`timeout = null`) to indicate keepalive
 * support. Server responds with a 16-bit idle-timeout in 100 ms units the
 * client may keep the connection open.
 * @docs https://datatracker.ietf.org/doc/html/rfc7828
 */
export class EdnsKeepalive implements EdnsOption {

    public ednsCode: number = EdnsOptionCode.KEEPALIVE;
    /**
     * Idle timeout in 100ms units, or `null` when the client signals support
     * without a value.
     */
    public timeout: number|null;

    public constructor(timeout: number|null = null) {
        this.timeout = timeout;
    }

    public static decode(reader: BufferReader, length: number): EdnsKeepalive {
        if (length === 0) {
            return new EdnsKeepalive(null);
        }

        if (length !== 2) {
            // RFC 7828 §3.1: any other length is a format error. Drain bytes
            // so the outer EDNS loop stays in sync, then signal "no value".
            for (let i = 0; i < length; i++) {
                reader.read(8);
            }

            return new EdnsKeepalive(null);
        }

        return new EdnsKeepalive(reader.read(16));
    }

    public encode(writer: BufferWriter): void {
        if (this.timeout !== null) {
            writer.write(this.timeout, 16);
        }
    }

}