import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import { BufferWriter } from './BufferWriter.js';
import { PacketName } from '../Packet/PacketName.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { NAPTR } from '../Packet/Types/NAPTR.js';
import { NSEC } from '../Packet/Types/NSEC.js';
import { RRSIG } from '../Packet/Types/RRSIG.js';
import { SOA } from '../Packet/Types/SOA.js';
import { SRV } from '../Packet/Types/SRV.js';
export var DnssecAlgorithm;
(function (DnssecAlgorithm) {
    DnssecAlgorithm[DnssecAlgorithm["RSASHA256"] = 8] = "RSASHA256";
    DnssecAlgorithm[DnssecAlgorithm["RSASHA512"] = 10] = "RSASHA512";
    DnssecAlgorithm[DnssecAlgorithm["ECDSAP256SHA256"] = 13] = "ECDSAP256SHA256";
    DnssecAlgorithm[DnssecAlgorithm["ECDSAP384SHA384"] = 14] = "ECDSAP384SHA384";
    DnssecAlgorithm[DnssecAlgorithm["ED25519"] = 15] = "ED25519";
})(DnssecAlgorithm || (DnssecAlgorithm = {}));
export var DnssecDigest;
(function (DnssecDigest) {
    DnssecDigest[DnssecDigest["SHA1"] = 1] = "SHA1";
    DnssecDigest[DnssecDigest["SHA256"] = 2] = "SHA256";
    DnssecDigest[DnssecDigest["SHA384"] = 4] = "SHA384";
})(DnssecDigest || (DnssecDigest = {}));
export class Dnssec {
    static _RAW_CANONICAL_TYPES = new Set([
        PacketTypes.A,
        PacketTypes.AAAA,
        PacketTypes.CAA,
        PacketTypes.DNSKEY,
        PacketTypes.DS,
        PacketTypes.NSEC3,
        PacketTypes.SPF,
        PacketTypes.SSHFP,
        PacketTypes.TLSA,
        PacketTypes.TXT,
    ]);
    static computeKeyTag(dnskey) {
        const rdata = Dnssec._dnskeyRdataBytes(dnskey);
        let ac = 0;
        for (let i = 0; i < rdata.length; i++) {
            ac += i & 1 ? rdata[i] : rdata[i] << 8;
        }
        ac += (ac >> 16) & 0xFFFF;
        return ac & 0xFFFF;
    }
    static computeDsDigest(owner, dnskey, digestType) {
        const ownerBuf = Dnssec._canonicalNameBytes(owner);
        const dnskeyBuf = Dnssec._dnskeyRdataBytes(dnskey);
        const input = Buffer.concat([ownerBuf, dnskeyBuf]);
        const hashName = Dnssec._hashNameForDigest(digestType);
        return crypto.createHash(hashName).update(input).digest('hex');
    }
    static verifyDs(owner, dnskey, ds) {
        if (ds.algorithm !== dnskey.algorithm) {
            return false;
        }
        if (Dnssec.computeKeyTag(dnskey) !== ds.keyTag) {
            return false;
        }
        const computed = Dnssec.computeDsDigest(owner, dnskey, ds.digestType);
        return computed.toLowerCase() === ds.digest.toLowerCase();
    }
    static verifyRrsig(owner, rrset, rrsig, dnskey, options = {}) {
        if (rrset.length === 0) {
            throw new Error('Dnssec.verifyRrsig: rrset is empty');
        }
        const rrType = rrset[0].packetType.type;
        if (rrsig.sigType !== rrType) {
            return false;
        }
        if (rrsig.algorithm !== dnskey.algorithm) {
            return false;
        }
        if (rrsig.keyTag !== Dnssec.computeKeyTag(dnskey)) {
            return false;
        }
        const ownerLabelCount = rrset[0].name.split('.').filter((l) => l.length > 0).length;
        if (rrsig.labels > ownerLabelCount) {
            return false;
        }
        if (options.skipValidityWindow !== true) {
            const now = options.now ?? Math.floor(Date.now() / 1000);
            const inception = Dnssec._parseSigDate(rrsig.inception);
            const expiration = Dnssec._parseSigDate(rrsig.expiration);
            if (now < inception || now > expiration) {
                return false;
            }
        }
        const input = Dnssec.buildSigningInput(owner, rrset, rrsig);
        const signature = Buffer.from(rrsig.signature, 'base64');
        return Dnssec._verifyAlgorithm(rrsig.algorithm, input, signature, dnskey);
    }
    static buildSigningInput(owner, rrset, rrsig) {
        const sigHeader = Dnssec._rrsigSignedHeader(rrsig);
        const signedOwner = Dnssec._reconstructSignedOwner(owner, rrsig.labels);
        const ownerBuf = Dnssec._canonicalNameBytes(signedOwner);
        const rrType = rrset[0].packetType.type;
        const rrClass = rrset[0].class;
        const canonicalRdatas = rrset.map((rr) => Dnssec._canonicalRdataBytes(rr));
        canonicalRdatas.sort(Buffer.compare);
        const parts = [sigHeader];
        for (const rdata of canonicalRdatas) {
            const fixed = Buffer.alloc(2 + 2 + 4 + 2);
            fixed.writeUInt16BE(rrType, 0);
            fixed.writeUInt16BE(rrClass, 2);
            fixed.writeUInt32BE(rrsig.originalTtl, 4);
            fixed.writeUInt16BE(rdata.length, 8);
            parts.push(ownerBuf, fixed, rdata);
        }
        return Buffer.concat(parts);
    }
    static _reconstructSignedOwner(owner, signerLabels) {
        const ownerLabels = owner.split('.').filter((l) => l.length > 0);
        if (signerLabels >= ownerLabels.length) {
            return owner;
        }
        const trailing = ownerLabels.slice(ownerLabels.length - signerLabels);
        return `*.${trailing.join('.')}`;
    }
    static _rrsigSignedHeader(rrsig) {
        const w = new BufferWriter();
        w.write(rrsig.sigType, 16);
        w.write(rrsig.algorithm, 8);
        w.write(rrsig.labels, 8);
        w.write(rrsig.originalTtl, 32);
        w.write(Dnssec._parseSigDate(rrsig.expiration), 32);
        w.write(Dnssec._parseSigDate(rrsig.inception), 32);
        w.write(rrsig.keyTag, 16);
        PacketName.encode(rrsig.signer.toLowerCase(), w);
        return w.toBuffer();
    }
    static _canonicalNameBytes(name) {
        const w = new BufferWriter();
        PacketName.encode(name.toLowerCase(), w);
        return w.toBuffer();
    }
    static _canonicalRdataBytes(resource) {
        const pt = resource.packetType;
        if (Dnssec._RAW_CANONICAL_TYPES.has(pt.type)) {
            return pt.encode(resource).subarray(2);
        }
        const w = new BufferWriter();
        switch (pt.type) {
            case PacketTypes.NS:
                PacketName.encode(pt.ns.toLowerCase(), w);
                return w.toBuffer();
            case PacketTypes.CNAME:
                PacketName.encode(pt.domain.toLowerCase(), w);
                return w.toBuffer();
            case PacketTypes.DNAME:
                PacketName.encode(pt.target.toLowerCase(), w);
                return w.toBuffer();
            case PacketTypes.PTR:
                PacketName.encode(pt.domain.toLowerCase(), w);
                return w.toBuffer();
            case PacketTypes.MX: {
                const mx = pt;
                w.write(mx.priority, 16);
                PacketName.encode(mx.exchange.toLowerCase(), w);
                return w.toBuffer();
            }
            case PacketTypes.SOA: {
                const soa = pt;
                const lowered = new SOA(soa.primary.toLowerCase(), soa.admin.toLowerCase(), soa.serial, soa.refresh, soa.retry, soa.expiration, soa.minimum);
                return lowered.encode({}).subarray(2);
            }
            case PacketTypes.SRV: {
                const srv = pt;
                const lowered = new SRV(srv.priority, srv.weight, srv.port, srv.target.toLowerCase());
                return lowered.encode({}).subarray(2);
            }
            case PacketTypes.NAPTR: {
                const naptr = pt;
                const lowered = new NAPTR(naptr.order, naptr.preference, naptr.flags, naptr.services, naptr.regexp, naptr.replacement.toLowerCase());
                return lowered.encode({}).subarray(2);
            }
            case PacketTypes.NSEC: {
                const nsec = pt;
                const lowered = new NSEC(nsec.nextDomain.toLowerCase(), nsec.rdtypes);
                return lowered.encode({}).subarray(2);
            }
            case PacketTypes.RRSIG: {
                const rr = pt;
                const lowered = new RRSIG(rr.sigType, rr.algorithm, rr.labels, rr.originalTtl, rr.expiration, rr.inception, rr.keyTag, rr.signer.toLowerCase(), rr.signature);
                return lowered.encode({}).subarray(2);
            }
            default:
                throw new Error(`Dnssec: canonical RDATA for type ${pt.type} is not implemented — ` +
                    'please add a case if your zone needs it');
        }
    }
    static _dnskeyRdataBytes(dnskey) {
        const wire = dnskey.encode({});
        return wire.subarray(2);
    }
    static _hashNameForDigest(digestType) {
        switch (digestType) {
            case DnssecDigest.SHA1:
                return 'sha1';
            case DnssecDigest.SHA256:
                return 'sha256';
            case DnssecDigest.SHA384:
                return 'sha384';
            default:
                throw new Error(`Dnssec: unsupported DS digest type ${digestType}`);
        }
    }
    static _parseSigDate(value) {
        if (/^\d+$/.test(value) && value.length !== 14) {
            return parseInt(value, 10);
        }
        if (!/^\d{14}$/.test(value)) {
            throw new Error(`Dnssec: invalid RRSIG date "${value}"`);
        }
        const year = parseInt(value.slice(0, 4), 10);
        const month = parseInt(value.slice(4, 6), 10);
        const day = parseInt(value.slice(6, 8), 10);
        const hour = parseInt(value.slice(8, 10), 10);
        const minute = parseInt(value.slice(10, 12), 10);
        const second = parseInt(value.slice(12, 14), 10);
        return Math.floor(Date.UTC(year, month - 1, day, hour, minute, second) / 1000);
    }
    static _verifyAlgorithm(algorithm, input, signature, dnskey) {
        switch (algorithm) {
            case DnssecAlgorithm.RSASHA256:
                return crypto.verify('sha256', input, Dnssec._rsaPublicKey(dnskey), signature);
            case DnssecAlgorithm.RSASHA512:
                return crypto.verify('sha512', input, Dnssec._rsaPublicKey(dnskey), signature);
            case DnssecAlgorithm.ECDSAP256SHA256:
                return crypto.verify('sha256', input, { key: Dnssec._ecdsaPublicKey(dnskey, 32, 'P-256'), dsaEncoding: 'ieee-p1363' }, signature);
            case DnssecAlgorithm.ECDSAP384SHA384:
                return crypto.verify('sha384', input, { key: Dnssec._ecdsaPublicKey(dnskey, 48, 'P-384'), dsaEncoding: 'ieee-p1363' }, signature);
            case DnssecAlgorithm.ED25519:
                return crypto.verify(null, input, Dnssec._ed25519PublicKey(dnskey), signature);
            default:
                throw new Error(`Dnssec: unsupported algorithm ${algorithm}`);
        }
    }
    static _rsaPublicKey(dnskey) {
        const rdata = Buffer.from(dnskey.key, 'base64');
        if (rdata.length < 2) {
            throw new Error('Dnssec: RSA DNSKEY too short');
        }
        let off;
        let explen;
        if (rdata[0] === 0) {
            if (rdata.length < 3) {
                throw new Error('Dnssec: RSA DNSKEY truncated explen');
            }
            explen = rdata.readUInt16BE(1);
            off = 3;
        }
        else {
            explen = rdata[0];
            off = 1;
        }
        if (off + explen >= rdata.length) {
            throw new Error('Dnssec: RSA DNSKEY truncated key body');
        }
        const exponent = rdata.subarray(off, off + explen);
        const modulus = rdata.subarray(off + explen);
        const jwk = {
            kty: 'RSA',
            n: modulus.toString('base64url'),
            e: exponent.toString('base64url'),
        };
        return crypto.createPublicKey({ key: jwk, format: 'jwk' });
    }
    static _ecdsaPublicKey(dnskey, curveBytes, jwkCurve) {
        const rdata = Buffer.from(dnskey.key, 'base64');
        if (rdata.length !== curveBytes * 2) {
            throw new Error(`Dnssec: ECDSA ${jwkCurve} DNSKEY must be ${curveBytes * 2} bytes, got ${rdata.length}`);
        }
        const jwk = {
            kty: 'EC',
            crv: jwkCurve,
            x: rdata.subarray(0, curveBytes).toString('base64url'),
            y: rdata.subarray(curveBytes).toString('base64url'),
        };
        return crypto.createPublicKey({ key: jwk, format: 'jwk' });
    }
    static _ed25519PublicKey(dnskey) {
        const rdata = Buffer.from(dnskey.key, 'base64');
        if (rdata.length !== 32) {
            throw new Error(`Dnssec: Ed25519 DNSKEY must be 32 bytes, got ${rdata.length}`);
        }
        const jwk = {
            kty: 'OKP',
            crv: 'Ed25519',
            x: rdata.toString('base64url'),
        };
        return crypto.createPublicKey({ key: jwk, format: 'jwk' });
    }
}
//# sourceMappingURL=Dnssec.js.map