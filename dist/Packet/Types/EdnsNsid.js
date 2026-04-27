import { Buffer } from 'buffer';
import { EdnsOptionCode } from './EdnsECS.js';
export class EdnsNsid {
    ednsCode = EdnsOptionCode.NSID;
    data;
    constructor(data = Buffer.alloc(0)) {
        this.data = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    }
    static decode(reader, length) {
        const bytes = [];
        for (let i = 0; i < length; i++) {
            bytes.push(reader.read(8));
        }
        return new EdnsNsid(Buffer.from(bytes));
    }
    encode(writer) {
        if (this.data.length > 0) {
            writer.writeBuffer(this.data);
        }
    }
}
//# sourceMappingURL=EdnsNsid.js.map