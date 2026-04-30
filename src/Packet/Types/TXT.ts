import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * TXT
 * @docs https://tools.ietf.org/html/rfc1035#section-3.3.14
 */
export class TXT extends PacketType {

    /**
     * Data
     */
    public data: string | string[];

    /**
     * Constructor
     * @param {string} data
     * @param {PacketTypes} type
     */
    public constructor(data: string | string[] = '', type: PacketTypes = PacketTypes.TXT) {
        super(type);
        this.data = data;
    }

    /**
     * Encode TXT Packet
     * @param {PacketResource} _resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        // make sure that resource data is an array of strings
        const characterStrings = Array.isArray(this.data) ? this.data : [this.data];

        // convert array of strings to array of buffers
        const characterStringBuffers = characterStrings.map((characterString) => {
            if (Buffer.isBuffer(characterString)) {
                return characterString;
            }

            if (typeof characterString === 'string') {
                return Buffer.from(characterString, 'utf8');
            }

            return false;
        }).filter((characterString) => {
            // remove invalid values from the array
            return characterString;
        });

        // calculate byte length of resource strings
        const bufferLength = characterStringBuffers.reduce((sum, characterStringBuffer) => {
            return sum + (characterStringBuffer === false ? 0 : characterStringBuffer.length);
        }, 0);

        // response length
        twriter.write(bufferLength + characterStringBuffers.length, 16);

        // write each string to output
        characterStringBuffers.forEach((abuffer) => {
            if (abuffer === false) {
                return;
            }

            // text length
            twriter.write(abuffer.length, 8);

            abuffer.forEach((c) => {
                twriter.write(c, 8);
            });
        });

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to TXT Packet.
     *
     * RFC 1035 §3.3.14: TXT RDATA is "one or more <character-string>"
     * — each prefixed with its 1-byte length. We preserve the
     * boundary by returning a `string[]`, one entry per
     * character-string. RFC 6763 §6.3 (DNS-SD) relies on the
     * boundary to distinguish individual `key=value` entries; the
     * earlier "concatenate everything into one string" behaviour
     * silently lost data for any TXT record with more than one
     * character-string.
     *
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        const strings: string[] = [];

        let bytesRead: number = 0;

        while (bytesRead < length) {
            const chunkLength = reader.read(8);
            bytesRead++;

            const bytes: number[] = [];

            for (let i = 0; i < chunkLength; i++) {
                bytes.push(reader.read(8));
                bytesRead++;
            }

            strings.push(Buffer.from(bytes).toString('utf8'));
        }

        const txt = new TXT();

        // Single character-string stays a plain string for backwards
        // compatibility with single-entry TXT consumers; multi-entry
        // (DNS-SD-style) TXTs land in the array form.
        txt.data = strings.length === 1 ? strings[0] : strings;

        return txt;
    }

}