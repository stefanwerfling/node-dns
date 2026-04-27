import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * DNAME — DNS delegation name (RFC 6672).
 *
 * Wire format is identical to CNAME — a single domain name in the RDATA —
 * but DNAME redirects an *entire subtree* rather than a single name. A
 * `foo.example.com DNAME bar.example.net` makes any query for
 * `*.foo.example.com` resolve under `*.bar.example.net`. The owner name
 * itself is not redirected — that's still the job of CNAME.
 *
 * Per RFC 6672 §3.1 the TARGET MUST NOT be DNS-compressed when written
 * out (the wire form has to be self-contained), but receivers MUST
 * tolerate compressed input. dns2ts already encodes domain-name fields
 * uncompressed across the board (see CNAME, NS, PTR — they all call
 * `PacketName.encode(name)` without passing the shared writer), so the
 * encoder is RFC-conformant by construction. Decoding goes through
 * `PacketName.decode`, which transparently follows compression pointers
 * if any are present.
 */
export class DNAME extends PacketType {

    /**
     * The target subtree.
     */
    public target: string;

    public constructor(target: string = '') {
        super(PacketTypes.DNAME);
        this.target = target;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;
        const buffer = PacketName.encode(this.target);

        twriter.write(buffer.length, 16);
        twriter.writeBuffer(buffer);

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader): PacketType {
        const target = PacketName.decode(reader);
        return new DNAME(target);
    }

}