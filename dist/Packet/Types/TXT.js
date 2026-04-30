import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class TXT extends PacketType {
    data;
    constructor(data = '', type = PacketTypes.TXT) {
        super(type);
        this.data = data;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const characterStrings = Array.isArray(this.data) ? this.data : [this.data];
        const characterStringBuffers = characterStrings.map((characterString) => {
            if (Buffer.isBuffer(characterString)) {
                return characterString;
            }
            if (typeof characterString === 'string') {
                return Buffer.from(characterString, 'utf8');
            }
            return false;
        }).filter((characterString) => {
            return characterString;
        });
        const bufferLength = characterStringBuffers.reduce((sum, characterStringBuffer) => {
            return sum + (characterStringBuffer === false ? 0 : characterStringBuffer.length);
        }, 0);
        twriter.write(bufferLength + characterStringBuffers.length, 16);
        characterStringBuffers.forEach((abuffer) => {
            if (abuffer === false) {
                return;
            }
            twriter.write(abuffer.length, 8);
            abuffer.forEach((c) => {
                twriter.write(c, 8);
            });
        });
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const strings = [];
        let bytesRead = 0;
        while (bytesRead < length) {
            const chunkLength = reader.read(8);
            bytesRead++;
            const bytes = [];
            for (let i = 0; i < chunkLength; i++) {
                bytes.push(reader.read(8));
                bytesRead++;
            }
            strings.push(Buffer.from(bytes).toString('utf8'));
        }
        const txt = new TXT();
        txt.data = strings.length === 1 ? strings[0] : strings;
        return txt;
    }
}
//# sourceMappingURL=TXT.js.map