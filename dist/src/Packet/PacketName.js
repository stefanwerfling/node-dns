"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PacketName = void 0;
const BufferReader_js_1 = require("../Lib/BufferReader.js");
const BufferWriter_js_1 = require("../Lib/BufferWriter.js");
class PacketName {
    static COPY = 0xc0;
    static decode(reader) {
        const treader = reader instanceof BufferReader_js_1.BufferReader ? reader : new BufferReader_js_1.BufferReader(reader);
        const name = [];
        let o;
        let len = treader.read(8);
        while (len) {
            if ((len & PacketName.COPY) === PacketName.COPY) {
                len -= PacketName.COPY;
                len = len << 8;
                const pos = len + treader.read(8);
                if (!o) {
                    o = treader.getOffset();
                }
                treader.setOffset(pos * 8);
                len = treader.read(8);
            }
            else {
                let part = '';
                while (len--) {
                    part += String.fromCharCode(treader.read(8));
                }
                name.push(part);
                len = treader.read(8);
            }
        }
        if (o) {
            treader.setOffset(0);
        }
        return name.join('.');
    }
    static encode(domain, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        domain.split('.').filter((part) => {
            return !!part;
        }).forEach((part) => {
            twriter.write(part.length, 8);
            part.split('').map((c) => {
                twriter.write(c.charCodeAt(0), 8);
                return c.charCodeAt(0);
            });
        });
        twriter.write(0, 8);
        return twriter.toBuffer();
    }
}
exports.PacketName = PacketName;
//# sourceMappingURL=PacketName.js.map