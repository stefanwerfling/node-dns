import { Buffer } from 'buffer';
import { createHmac, timingSafeEqual } from 'crypto';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketClass } from './PacketClass.js';
import { PacketName } from './PacketName.js';
import { PacketResource } from './PacketResource.js';
import { TsigAlgorithm } from './TsigKey.js';
import { TSIG, TsigError } from './Types/TSIG.js';
export class Tsig {
    static ARCOUNT_OFFSET = 10;
    static canonicalName(name) {
        const lower = name.toLowerCase();
        return lower.endsWith('.') ? lower.slice(0, -1) : lower;
    }
    static hashName(algorithm) {
        const lowered = Tsig.canonicalName(algorithm);
        switch (lowered) {
            case Tsig.canonicalName(TsigAlgorithm.HMAC_MD5):
                return 'md5';
            case Tsig.canonicalName(TsigAlgorithm.HMAC_SHA1):
                return 'sha1';
            case Tsig.canonicalName(TsigAlgorithm.HMAC_SHA224):
                return 'sha224';
            case Tsig.canonicalName(TsigAlgorithm.HMAC_SHA256):
                return 'sha256';
            case Tsig.canonicalName(TsigAlgorithm.HMAC_SHA384):
                return 'sha384';
            case Tsig.canonicalName(TsigAlgorithm.HMAC_SHA512):
                return 'sha512';
            default:
                throw new Error(`TSIG: unsupported algorithm "${algorithm}"`);
        }
    }
    static encodeTsigVariables(keyName, algorithm, timeSigned, fudge, error, otherData) {
        const writer = new BufferWriter();
        PacketName.encode(keyName.toLowerCase(), writer);
        writer.write(PacketClass.ANY, 16);
        writer.write(0, 32);
        PacketName.encode(algorithm.toLowerCase(), writer);
        const divisor = 0x100000000;
        writer.write(Math.floor(timeSigned / divisor), 16);
        writer.write(timeSigned % divisor, 32);
        writer.write(fudge, 16);
        writer.write(error, 16);
        writer.write(otherData.length, 16);
        if (otherData.length > 0) {
            writer.writeBuffer(otherData);
        }
        return writer.toBuffer();
    }
    static encodeRequestMacPrefix(mac) {
        const prefix = Buffer.alloc(2 + mac.length);
        prefix.writeUInt16BE(mac.length, 0);
        mac.copy(prefix, 2);
        return prefix;
    }
    static sign(packet, key, options = {}) {
        const timeSigned = options.timeSigned === undefined ? Math.floor(Date.now() / 1000) : options.timeSigned;
        const fudge = options.fudge === undefined ? 300 : options.fudge;
        const error = options.error === undefined ? TsigError.NOERROR : options.error;
        const otherData = options.otherData === undefined ? Buffer.alloc(0) : options.otherData;
        const preBytes = packet.toBuffer();
        const macInputMsg = Buffer.from(preBytes);
        macInputMsg.writeUInt16BE(packet.header.arcount + 1, Tsig.ARCOUNT_OFFSET);
        const tsigVars = Tsig.encodeTsigVariables(key.name, key.algorithm, timeSigned, fudge, error, otherData);
        const hmac = createHmac(Tsig.hashName(key.algorithm), key.secret);
        if (options.requestMac) {
            hmac.update(Tsig.encodeRequestMacPrefix(options.requestMac));
        }
        hmac.update(macInputMsg);
        hmac.update(tsigVars);
        const mac = hmac.digest();
        const tsigRecord = new TSIG(key.algorithm, timeSigned, fudge, mac, packet.header.id, error, otherData);
        const tsigResource = new PacketResource(key.name, tsigRecord, PacketClass.ANY, 0);
        const tsigRRBytes = PacketResource.encode(tsigResource);
        const final = Buffer.concat([macInputMsg, tsigRRBytes]);
        packet.additionals.push(tsigResource);
        packet.header.arcount = packet.additionals.length;
        return {
            buffer: final,
            mac: mac,
            tsig: tsigRecord
        };
    }
    static verify(packet, receivedBytes, key, options = {}) {
        const lastAdd = packet.additionals[packet.additionals.length - 1];
        if (!lastAdd || !(lastAdd.packetType instanceof TSIG)) {
            return {
                valid: false,
                reason: 'no TSIG record at the end of the Additional section'
            };
        }
        const tsig = lastAdd.packetType;
        if (lastAdd.byteStart === undefined) {
            return {
                valid: false,
                reason: 'TSIG resource has no byteStart offset (parse via Packet.parse)',
                tsig: tsig
            };
        }
        if (Tsig.canonicalName(lastAdd.name) !== Tsig.canonicalName(key.name)) {
            return {
                valid: false,
                reason: `TSIG key name mismatch: expected ${key.name}, got ${lastAdd.name}`,
                tsig: tsig
            };
        }
        if (Tsig.canonicalName(tsig.algorithm) !== Tsig.canonicalName(key.algorithm)) {
            return {
                valid: false,
                reason: `TSIG algorithm mismatch: expected ${key.algorithm}, got ${tsig.algorithm}`,
                tsig: tsig
            };
        }
        if (!options.skipTimeCheck) {
            const now = options.now === undefined ? Math.floor(Date.now() / 1000) : options.now;
            const delta = Math.abs(now - tsig.timeSigned);
            if (delta > tsig.fudge) {
                return {
                    valid: false,
                    reason: `TSIG timestamp outside fudge window (delta=${delta}s, fudge=${tsig.fudge}s)`,
                    tsig: tsig
                };
            }
        }
        const sliceEnd = lastAdd.byteStart;
        if (sliceEnd > receivedBytes.length) {
            return {
                valid: false,
                reason: 'TSIG offset beyond buffer',
                tsig: tsig
            };
        }
        const macInput = receivedBytes.subarray(0, sliceEnd);
        const tsigVars = Tsig.encodeTsigVariables(lastAdd.name, tsig.algorithm, tsig.timeSigned, tsig.fudge, tsig.error, tsig.otherData);
        let hashName;
        try {
            hashName = Tsig.hashName(tsig.algorithm);
        }
        catch (e) {
            return {
                valid: false,
                reason: e instanceof Error ? e.message : String(e),
                tsig: tsig
            };
        }
        const hmac = createHmac(hashName, key.secret);
        if (options.requestMac) {
            hmac.update(Tsig.encodeRequestMacPrefix(options.requestMac));
        }
        hmac.update(macInput);
        hmac.update(tsigVars);
        const expected = hmac.digest();
        if (expected.length !== tsig.mac.length || !timingSafeEqual(expected, tsig.mac)) {
            return {
                valid: false,
                reason: 'TSIG MAC verification failed',
                tsig: tsig
            };
        }
        return {
            valid: true,
            tsig: tsig
        };
    }
}
//# sourceMappingURL=Tsig.js.map