import { Buffer } from 'buffer';
import { EdnsOptionCode } from './EdnsECS.js';
export class EdnsPadding {
    ednsCode = EdnsOptionCode.PADDING;
    length;
    constructor(length = 0) {
        this.length = length;
    }
    static decode(reader, length) {
        for (let i = 0; i < length; i++) {
            reader.read(8);
        }
        return new EdnsPadding(length);
    }
    encode(writer) {
        if (this.length > 0) {
            writer.writeBuffer(Buffer.alloc(this.length));
        }
    }
}
//# sourceMappingURL=EdnsPadding.js.map