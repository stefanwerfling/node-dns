import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
import { EdnsECS, EdnsOptionCode } from './EdnsECS.js';
import { debuglog } from 'util';
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
            if (rdata.ednsCode === EdnsOptionCode.ECS && rdata instanceof EdnsECS) {
                const optWriter = new BufferWriter();
                rdata.encode(optWriter);
                const optBuffer = optWriter.toBuffer();
                rdataWriter.write(rdata.ednsCode, 16);
                rdataWriter.write(optBuffer.length, 16);
                rdataWriter.writeBuffer(optWriter);
            }
            else {
                debug('node-dns > unknown EDNS rdata encoder %d', rdata.ednsCode);
            }
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
            if (optionCode === EdnsOptionCode.ECS) {
                edns.rdata.push(EdnsECS.decode(reader, optionLength));
            }
            else {
                for (let i = 0; i < optionLength; i++) {
                    reader.read(8);
                }
                debug('node-dns > unknown EDNS rdata decoder %d', optionCode);
            }
            remaining = remaining - 4 - optionLength;
        }
        return edns;
    }
}
//# sourceMappingURL=EDNS.js.map