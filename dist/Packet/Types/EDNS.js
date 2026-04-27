import { debuglog } from 'util';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
import { EdnsCookie } from './EdnsCookie.js';
import { EdnsECS, EdnsOptionCode } from './EdnsECS.js';
import { EdnsExtendedError } from './EdnsExtendedError.js';
import { EdnsKeepalive } from './EdnsKeepalive.js';
import { EdnsNsid } from './EdnsNsid.js';
import { EdnsPadding } from './EdnsPadding.js';
const debug = debuglog('dns2');
export { EdnsOptionCode, EdnsECS };
export class EDNS extends PacketType {
    rdata;
    constructor(rdata = []) {
        super(PacketTypes.EDNS);
        this.rdata = rdata;
    }
    static createResource(rdata) {
        return new PacketResource('', new EDNS(rdata), 512, 0);
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const rdataWriter = new BufferWriter();
        for (const rdata of this.rdata) {
            const optWriter = new BufferWriter();
            rdata.encode(optWriter);
            const optBuffer = optWriter.toBuffer();
            rdataWriter.write(rdata.ednsCode, 16);
            rdataWriter.write(optBuffer.length, 16);
            rdataWriter.writeBuffer(optWriter);
        }
        const rdataBuffer = rdataWriter.toBuffer();
        twriter.write(rdataBuffer.length, 16);
        twriter.writeBuffer(rdataWriter);
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const edns = new EDNS();
        let remaining = length;
        while (remaining > 0) {
            const optionCode = reader.read(16);
            const optionLength = reader.read(16);
            const option = EDNS._decodeOption(optionCode, optionLength, reader);
            if (option) {
                edns.rdata.push(option);
            }
            remaining = remaining - 4 - optionLength;
        }
        return edns;
    }
    static _decodeOption(code, length, reader) {
        switch (code) {
            case EdnsOptionCode.ECS:
                return EdnsECS.decode(reader, length);
            case EdnsOptionCode.COOKIE:
                return EdnsCookie.decode(reader, length);
            case EdnsOptionCode.PADDING:
                return EdnsPadding.decode(reader, length);
            case EdnsOptionCode.NSID:
                return EdnsNsid.decode(reader, length);
            case EdnsOptionCode.KEEPALIVE:
                return EdnsKeepalive.decode(reader, length);
            case EdnsOptionCode.EDE:
                return EdnsExtendedError.decode(reader, length);
            default:
                for (let i = 0; i < length; i++) {
                    reader.read(8);
                }
                debug('node-dns > unknown EDNS rdata decoder %d', code);
                return null;
        }
    }
}
//# sourceMappingURL=EDNS.js.map