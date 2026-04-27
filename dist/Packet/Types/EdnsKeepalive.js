import { EdnsOptionCode } from './EdnsECS.js';
export class EdnsKeepalive {
    ednsCode = EdnsOptionCode.KEEPALIVE;
    timeout;
    constructor(timeout = null) {
        this.timeout = timeout;
    }
    static decode(reader, length) {
        if (length === 0) {
            return new EdnsKeepalive(null);
        }
        if (length !== 2) {
            for (let i = 0; i < length; i++) {
                reader.read(8);
            }
            return new EdnsKeepalive(null);
        }
        return new EdnsKeepalive(reader.read(16));
    }
    encode(writer) {
        if (this.timeout !== null) {
            writer.write(this.timeout, 16);
        }
    }
}
//# sourceMappingURL=EdnsKeepalive.js.map