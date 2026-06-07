import {Buffer} from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * OPENPGPKEY — DANE for OpenPGP (RFC 7929). The RDATA is the raw
 * OpenPGP transferable public key (the same byte sequence that the
 * key packet uses on the wire, OpenPGP §11.1).
 *
 * Owner name convention: `<sha256(local-part)[0..56]>._openpgpkey.
 * <domain>`. The owner format is RFC 7929 §3 — this class only
 * concerns itself with the RDATA byte container.
 *
 * Presentation form: base64-encoded blob. We store the bytes hex-
 * encoded internally to mirror the existing DS / SSHFP / TLSA
 * convention, but `presentation()` returns the RFC-7929 base64 form
 * for zone-file output.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc7929
 */
export class OPENPGPKEY extends PacketType {

    public publicKey: string;

    public constructor(publicKey: string = '') {
        super(PacketTypes.OPENPGPKEY);
        this.publicKey = publicKey;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const keyBuf = Buffer.from(this.publicKey, 'hex');

        twriter.write(keyBuf.length, 16);

        for (const byte of keyBuf) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const keyBytes: number[] = [];

        for (let i = 0; i < length; i++) {
            keyBytes.push(reader.read(8));
        }

        return new OPENPGPKEY(Buffer.from(keyBytes).toString('hex'));
    }

}