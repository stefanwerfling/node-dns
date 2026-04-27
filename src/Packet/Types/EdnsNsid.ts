import {Buffer} from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {EdnsOption, EdnsOptionCode} from './EdnsECS.js';

/**
 * EDNS(0) Name Server Identifier (NSID) option (RFC 5001).
 *
 * In a query the option is sent with empty payload to ask the server for its
 * identifier. In the response the server includes its NSID as opaque bytes
 * (often a hostname or instance id, but not constrained by spec).
 * @docs https://datatracker.ietf.org/doc/html/rfc5001
 */
export class EdnsNsid implements EdnsOption {

    public ednsCode: number = EdnsOptionCode.NSID;
    public data: Buffer;

    public constructor(data: Buffer|string = Buffer.alloc(0)) {
        this.data = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    }

    public static decode(reader: BufferReader, length: number): EdnsNsid {
        const bytes: number[] = [];

        for (let i = 0; i < length; i++) {
            bytes.push(reader.read(8));
        }

        return new EdnsNsid(Buffer.from(bytes));
    }

    public encode(writer: BufferWriter): void {
        if (this.data.length > 0) {
            writer.writeBuffer(this.data);
        }
    }

}