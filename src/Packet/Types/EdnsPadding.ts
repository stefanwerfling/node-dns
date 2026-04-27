import {Buffer} from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {EdnsOption, EdnsOptionCode} from './EdnsECS.js';

/**
 * EDNS(0) Padding option (RFC 7830).
 *
 * Pads a DNS message to a chosen block size to defeat traffic analysis on
 * encrypted transports (DoT/DoH). Payload is `length` octets that MUST be
 * zero on the wire; we always emit and accept zero bytes per spec.
 * @docs https://datatracker.ietf.org/doc/html/rfc7830
 */
export class EdnsPadding implements EdnsOption {

    public ednsCode: number = EdnsOptionCode.PADDING;
    public length: number;

    public constructor(length: number = 0) {
        this.length = length;
    }

    public static decode(reader: BufferReader, length: number): EdnsPadding {
        // Drain padding bytes — content is required to be zero by RFC 7830 §3
        // but we are tolerant on receive.
        for (let i = 0; i < length; i++) {
            reader.read(8);
        }

        return new EdnsPadding(length);
    }

    public encode(writer: BufferWriter): void {
        if (this.length > 0) {
            writer.writeBuffer(Buffer.alloc(this.length));
        }
    }

}