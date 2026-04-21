import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export var TsigError;
(function (TsigError) {
    TsigError[TsigError["NOERROR"] = 0] = "NOERROR";
    TsigError[TsigError["BADSIG"] = 16] = "BADSIG";
    TsigError[TsigError["BADKEY"] = 17] = "BADKEY";
    TsigError[TsigError["BADTIME"] = 18] = "BADTIME";
    TsigError[TsigError["BADTRUNC"] = 22] = "BADTRUNC";
})(TsigError || (TsigError = {}));
export class TSIG extends PacketType {
    algorithm;
    timeSigned;
    fudge;
    mac;
    originalId;
    error;
    otherData;
    constructor(algorithm = 'hmac-sha256.', timeSigned = 0, fudge = 300, mac = Buffer.alloc(0), originalId = 0, error = TsigError.NOERROR, otherData = Buffer.alloc(0)) {
        super(PacketTypes.TSIG);
        this.algorithm = algorithm;
        this.timeSigned = timeSigned;
        this.fudge = fudge;
        this.mac = mac;
        this.originalId = originalId;
        this.error = error;
        this.otherData = otherData;
    }
    static splitUint48(value) {
        const divisor = 0x100000000;
        return {
            hi: Math.floor(value / divisor),
            lo: value % divisor
        };
    }
    static joinUint48(hi, lo) {
        return (hi * 0x100000000) + lo;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const rdataWriter = new BufferWriter();
        PacketName.encode(this.algorithm, rdataWriter);
        const ts = TSIG.splitUint48(this.timeSigned);
        rdataWriter.write(ts.hi, 16);
        rdataWriter.write(ts.lo, 32);
        rdataWriter.write(this.fudge, 16);
        rdataWriter.write(this.mac.length, 16);
        rdataWriter.writeBuffer(this.mac);
        rdataWriter.write(this.originalId, 16);
        rdataWriter.write(this.error, 16);
        rdataWriter.write(this.otherData.length, 16);
        rdataWriter.writeBuffer(this.otherData);
        const rdataBuf = rdataWriter.toBuffer();
        twriter.write(rdataBuf.length, 16);
        twriter.writeBuffer(rdataWriter);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const rawAlgorithm = PacketName.decode(reader);
        const algorithm = rawAlgorithm.endsWith('.') ? rawAlgorithm : `${rawAlgorithm}.`;
        const hi = reader.read(16);
        const lo = reader.read(32);
        const timeSigned = TSIG.joinUint48(hi, lo);
        const fudge = reader.read(16);
        const macSize = reader.read(16);
        const macBytes = [];
        for (let i = 0; i < macSize; i++) {
            macBytes.push(reader.read(8));
        }
        const originalId = reader.read(16);
        const error = reader.read(16);
        const otherLen = reader.read(16);
        const otherBytes = [];
        for (let i = 0; i < otherLen; i++) {
            otherBytes.push(reader.read(8));
        }
        return new TSIG(algorithm, timeSigned, fudge, Buffer.from(macBytes), originalId, error, Buffer.from(otherBytes));
    }
}
//# sourceMappingURL=TSIG.js.map