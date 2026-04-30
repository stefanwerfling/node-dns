import assert from 'assert';
import * as crypto from 'crypto';
import {Dnssec, DnssecAlgorithm, DnssecDigest} from '../Lib/Dnssec.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {DNSKEY} from '../Packet/Types/DNSKEY.js';
import {DS} from '../Packet/Types/DS.js';
import {NS} from '../Packet/Types/NS.js';
import {NSEC} from '../Packet/Types/NSEC.js';
import {NSEC3} from '../Packet/Types/NSEC3.js';
import {RRSIG} from '../Packet/Types/RRSIG.js';
import {RCODE, RecursiveResolver, RecursiveResolverTransport} from '../Resolver/RecursiveResolver.js';
import {TrustAnchors} from '../Resolver/TrustAnchor.js';
import {test} from './test.js';

const SIGN_INCEPTION = '20240101000000';
const SIGN_EXPIRATION = '20300101000000';
const NOW_SEC = 1748736000;

/**
 * Generate an Ed25519 signing key plus matching DNSKEY.
 */
const csk = (): {dnskey: DNSKEY; privateKey: crypto.KeyObject;} => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    return {
        dnskey: Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519),
        privateKey: privateKey
    };
};

const signRrset = (
    owner: string,
    rrset: PacketResource[],
    key: {dnskey: DNSKEY; privateKey: crypto.KeyObject;},
    signer: string
): RRSIG => {
    return Dnssec.signRrset(owner, rrset, key.dnskey, key.privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
        signer: signer
    });
};

/**
 * Build a 3-tier signed mock universe:
 *
 *   root (.)              — trust anchor
 *     │
 *     com.                — delegated by root, DS at root authenticates
 *     │
 *     example.com.        — delegated by com, DS at com authenticates
 *       www.example.com   — A record signed by example.com's ZSK
 *
 * Returns a configured `RecursiveResolver` plus the trust anchor that
 * matches root's KSK.
 */
const buildSignedUniverse = (): {
    resolver: RecursiveResolver;
    transport: ReturnType<typeof buildSignedUniverseTransport>;
} => {
    const u = buildSignedUniverseTransport();

    const resolver = new RecursiveResolver({
        transport: u.transport,
        rootHints: [{name: 'root.test.', ipv4: '10.0.0.1'}],
        use0x20: false,
        dnssec: {
            trustAnchors: [TrustAnchors.of('.', u.rootDs)],
            verifyOptions: {now: NOW_SEC}
        }
    });

    return {resolver: resolver, transport: u};
};

const buildSignedUniverseTransport = (): {
    transport: RecursiveResolverTransport;
    rootDs: DS;
    counts: Map<string, number>;
} => {
    // Three signing keys: one per tier.
    const rootKey = csk();
    const comKey = csk();
    const exampleKey = csk();

    // DS records bind parent to child.
    const dsCom = new DS(
        Dnssec.computeKeyTag(comKey.dnskey),
        comKey.dnskey.algorithm,
        DnssecDigest.SHA256,
        Dnssec.computeDsDigest('com.', comKey.dnskey, DnssecDigest.SHA256)
    );

    const dsExample = new DS(
        Dnssec.computeKeyTag(exampleKey.dnskey),
        exampleKey.dnskey.algorithm,
        DnssecDigest.SHA256,
        Dnssec.computeDsDigest('example.com.', exampleKey.dnskey, DnssecDigest.SHA256)
    );

    // Root anchor — DS pointing at the root's own KSK.
    const rootDs = new DS(
        Dnssec.computeKeyTag(rootKey.dnskey),
        rootKey.dnskey.algorithm,
        DnssecDigest.SHA256,
        Dnssec.computeDsDigest('.', rootKey.dnskey, DnssecDigest.SHA256)
    );

    // Pre-build the DNSKEY RRsets and their RRSIGs.
    const rootDnskeyRecord = new PacketResource('.', rootKey.dnskey, PacketClass.IN, 3600);
    const comDnskeyRecord = new PacketResource('com.', comKey.dnskey, PacketClass.IN, 3600);
    const exampleDnskeyRecord = new PacketResource('example.com.', exampleKey.dnskey, PacketClass.IN, 3600);

    const rootDnskeySig = signRrset('.', [rootDnskeyRecord], rootKey, '.');
    const comDnskeySig = signRrset('com.', [comDnskeyRecord], comKey, 'com.');
    const exampleDnskeySig = signRrset('example.com.', [exampleDnskeyRecord], exampleKey, 'example.com.');

    // DS RRsets (signed by the parent zone).
    const dsComRec = new PacketResource('com.', dsCom, PacketClass.IN, 3600);
    const dsComSig = signRrset('com.', [dsComRec], rootKey, '.');

    const dsExampleRec = new PacketResource('example.com.', dsExample, PacketClass.IN, 3600);
    const dsExampleSig = signRrset('example.com.', [dsExampleRec], comKey, 'com.');

    // Final A record at www.example.com., signed by example.com.
    const wwwA = new PacketResource('www.example.com.', new A('198.51.100.7'), PacketClass.IN, 300);
    const wwwSig = signRrset('www.example.com.', [wwwA], exampleKey, 'example.com.');

    const counts = new Map<string, number>();

    /**
     * The transport routes by (server-IP, qname, qtype). Servers map
     * to zones: 10.0.0.1 = root, 10.0.0.2 = com, 10.0.0.3 = example.com.
     */
    const transport: RecursiveResolverTransport = async(serverIp, _port, query) => {
        counts.set(serverIp, (counts.get(serverIp) ?? 0) + 1);

        const q = query.questions[0];
        const qnameNorm = q.name.toLowerCase().replace(/\.$/u, '');
        const qtype = q.type;

        const reply = (answers: PacketResource[], rcode: number = 0, aa: boolean = true,
            authorities: PacketResource[] = [],
            additionals: PacketResource[] = []): Packet => {
            const r = new Packet();
            r.header.id = query.header.id;
            r.header.qr = 1;
            r.header.aa = aa ? 1 : 0;
            r.header.rcode = rcode;
            r.questions = query.questions.slice();
            r.answers = answers;
            r.authorities = authorities;
            r.additionals = additionals;
            return r;
        };

        // -------- root server (10.0.0.1) --------
        if (serverIp === '10.0.0.1') {
            // Authoritative for the root zone itself: DNSKEY of root.
            if ((qnameNorm === '' || q.name === '.') && qtype === PacketTypes.DNSKEY) {
                return reply([
                    rootDnskeyRecord,
                    new PacketResource('.', rootDnskeySig, PacketClass.IN, 3600)
                ]);
            }

            // DS for com — authoritative answer from root.
            if (qnameNorm === 'com' && qtype === PacketTypes.DS) {
                return reply([
                    dsComRec,
                    new PacketResource('com.', dsComSig, PacketClass.IN, 3600)
                ]);
            }

            // Anything under .com or .example.com — referral to com.
            return reply([], 0, false, [
                new PacketResource('com.', new NS('a.gtld.com.'), PacketClass.IN, 3600)
            ], [
                new PacketResource('a.gtld.com.', new A('10.0.0.2'), PacketClass.IN, 3600)
            ]);
        }

        // -------- com server (10.0.0.2) --------
        if (serverIp === '10.0.0.2') {
            if (qnameNorm === 'com' && qtype === PacketTypes.DNSKEY) {
                return reply([
                    comDnskeyRecord,
                    new PacketResource('com.', comDnskeySig, PacketClass.IN, 3600)
                ]);
            }

            if (qnameNorm === 'example.com' && qtype === PacketTypes.DS) {
                return reply([
                    dsExampleRec,
                    new PacketResource('example.com.', dsExampleSig, PacketClass.IN, 3600)
                ]);
            }

            // Anything under example.com — referral to example.com auth.
            return reply([], 0, false, [
                new PacketResource('example.com.', new NS('ns.example.com.'), PacketClass.IN, 3600)
            ], [
                new PacketResource('ns.example.com.', new A('10.0.0.3'), PacketClass.IN, 3600)
            ]);
        }

        // -------- example.com server (10.0.0.3) --------
        if (serverIp === '10.0.0.3') {
            if (qnameNorm === 'example.com' && qtype === PacketTypes.DNSKEY) {
                return reply([
                    exampleDnskeyRecord,
                    new PacketResource('example.com.', exampleDnskeySig, PacketClass.IN, 3600)
                ]);
            }

            if (qnameNorm === 'www.example.com' && qtype === PacketTypes.A) {
                return reply([
                    wwwA,
                    new PacketResource('www.example.com.', wwwSig, PacketClass.IN, 300)
                ]);
            }

            // Anything else — refuse.
            return reply([], RCODE.REFUSED);
        }

        throw new Error(`unknown server ${serverIp}`);
    };

    return {transport: transport, rootDs: rootDs, counts: counts};
};

/* ----------------------------------------------------------------------- */

test('RecursiveResolver#dnssec disabled by default — no AD bit, no SERVFAIL', async() => {
    const universe = buildSignedUniverseTransport();
    const resolver = new RecursiveResolver({
        transport: universe.transport,
        rootHints: [{name: 'root.test.', ipv4: '10.0.0.1'}],
        use0x20: false
    });

    const r = await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    // AD bit is bit 1 (value 2) of z; should be 0.
    // eslint-disable-next-line no-bitwise
    assert.equal((r.header.z & 0b010) >> 1, 0);
});

test('RecursiveResolver#dnssec validates a fully-signed answer end-to-end (AD=1)', async() => {
    const {resolver} = buildSignedUniverse();

    const r = await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal((r.answers[0].packetType as A).address, '198.51.100.7');
    // eslint-disable-next-line no-bitwise
    assert.equal((r.header.z & 0b010) >> 1, 1, 'AD bit must be set on a fully-validated answer');
});

test('RecursiveResolver#dnssec returns SERVFAIL when an RRset signature is forged', async() => {
    const {resolver, transport} = buildSignedUniverse();

    // Pre-warm the resolver so we can mutate one record before the second query.
    await resolver.resolve('www.example.com', PacketTypes.A);
    resolver.cache().clear();

    // Override the example.com handler to ship a tampered RRSIG.
    const originalTransport = transport.transport;
    let tampered: RecursiveResolverTransport = async(serverIp, port, query) => {
        const r = await originalTransport(serverIp, port, query);

        if (serverIp === '10.0.0.3' && query.questions[0]?.type === PacketTypes.A) {
            // Replace the signature in the RRSIG of the A answer.
            for (const a of r.answers) {
                if (a.packetType.type === PacketTypes.RRSIG) {
                    (a.packetType as RRSIG).signature = Buffer.alloc(64).toString('base64');
                }
            }
        }

        return r;
    };

    const tamperedResolver = new RecursiveResolver({
        transport: tampered,
        rootHints: [{name: 'root.test.', ipv4: '10.0.0.1'}],
        use0x20: false,
        dnssec: {
            trustAnchors: [TrustAnchors.of('.', transport.rootDs)],
            verifyOptions: {now: NOW_SEC}
        }
    });

    const r = await tamperedResolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.SERVFAIL);
});

test('RecursiveResolver#dnssec returns SERVFAIL when a wrong trust anchor is configured', async() => {
    const universe = buildSignedUniverseTransport();
    const wrongAnchor = TrustAnchors.of('.', new DS(99, 8, 2, '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'));

    const resolver = new RecursiveResolver({
        transport: universe.transport,
        rootHints: [{name: 'root.test.', ipv4: '10.0.0.1'}],
        use0x20: false,
        dnssec: {
            trustAnchors: [wrongAnchor],
            verifyOptions: {now: NOW_SEC}
        }
    });

    const r = await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.SERVFAIL);
});

test('RecursiveResolver#dnssec passes through with AD=0 when no anchor covers the zone', async() => {
    const universe = buildSignedUniverseTransport();

    const resolver = new RecursiveResolver({
        transport: universe.transport,
        rootHints: [{name: 'root.test.', ipv4: '10.0.0.1'}],
        use0x20: false,
        dnssec: {
            trustAnchors: [TrustAnchors.of('other.test.', universe.rootDs)],
            verifyOptions: {now: NOW_SEC}
        }
    });

    const r = await resolver.resolve('www.example.com', PacketTypes.A);
    // No anchor covers `.com` — `indeterminate`. Result passes through with AD=0.
    assert.equal(r.header.rcode, RCODE.NOERROR);
    // eslint-disable-next-line no-bitwise
    assert.equal((r.header.z & 0b010) >> 1, 0);
});

/* ----------------------------------------------------------------------- */
/*  Insecure delegations (RFC 4035 §5.2 / RFC 5155 §6 opt-out)              */
/* ----------------------------------------------------------------------- */

/**
 * Build a 3-tier universe (root → com → unsigned.com) where the
 * `com.`-side proof of "no DS at unsigned.com." is configurable.
 * The unsigned auth itself returns plain (unsigned) answers.
 *
 *  - `'nsec'` — com ships an NSEC at owner == unsigned.com. with
 *    bitmap [NS, RRSIG], signed by com's ZSK.
 *  - `'nsec3-optout'` — com ships an NSEC3 with the opt-out flag set,
 *    whose hash range covers hash(unsigned.com.).
 *  - `'missing'` — com ships an empty answer with NO proof (forge
 *    attempt). The resolver must surface this as SERVFAIL.
 */
const buildInsecureUniverse = (proof: 'nsec' | 'nsec3-optout' | 'missing'): {
    resolver: RecursiveResolver;
    counts: Map<string, number>;
} => {
    const rootKey = csk();
    const comKey = csk();

    const dsCom = new DS(
        Dnssec.computeKeyTag(comKey.dnskey),
        comKey.dnskey.algorithm,
        DnssecDigest.SHA256,
        Dnssec.computeDsDigest('com.', comKey.dnskey, DnssecDigest.SHA256)
    );

    const rootDs = new DS(
        Dnssec.computeKeyTag(rootKey.dnskey),
        rootKey.dnskey.algorithm,
        DnssecDigest.SHA256,
        Dnssec.computeDsDigest('.', rootKey.dnskey, DnssecDigest.SHA256)
    );

    const rootDnskeyRecord = new PacketResource('.', rootKey.dnskey, PacketClass.IN, 3600);
    const comDnskeyRecord = new PacketResource('com.', comKey.dnskey, PacketClass.IN, 3600);

    const rootDnskeySig = signRrset('.', [rootDnskeyRecord], rootKey, '.');
    const comDnskeySig = signRrset('com.', [comDnskeyRecord], comKey, 'com.');

    const dsComRec = new PacketResource('com.', dsCom, PacketClass.IN, 3600);
    const dsComSig = signRrset('com.', [dsComRec], rootKey, '.');

    // The unsigned-delegation proof — only the NSEC/NSEC3 records,
    // no DS in answer.
    let proofRecords: PacketResource[] = [];

    if (proof === 'nsec') {
        const nsecRec = new PacketResource(
            'unsigned.com.',
            new NSEC('zzz.com.', [PacketTypes.NS, PacketTypes.RRSIG, PacketTypes.NSEC]),
            PacketClass.IN, 3600
        );
        const nsecSig = signRrset('unsigned.com.', [nsecRec], comKey, 'com.');
        proofRecords = [
            nsecRec,
            new PacketResource('unsigned.com.', nsecSig, PacketClass.IN, 3600)
        ];
    } else if (proof === 'nsec3-optout') {
        const salt = 'aabbcc';
        const targetHash = Dnssec.nsec3Hash('unsigned.com.', salt, 0);
        const owner = Buffer.from(targetHash);
        owner[19] = (owner[19] - 1) & 0xff;
        const next = Buffer.from(targetHash);
        next[19] = (next[19] + 1) & 0xff;
        const ownerLabel = Dnssec.base32hexEncode(owner).toLowerCase();
        const nsec3 = new NSEC3(1, 0x01 /* opt-out */, 0, salt, next.toString('hex'),
            [PacketTypes.NS, PacketTypes.RRSIG]);
        const nsec3Rec = new PacketResource(
            `${ownerLabel}.com.`,
            nsec3,
            PacketClass.IN, 3600
        );
        const nsec3Sig = signRrset(`${ownerLabel}.com.`, [nsec3Rec], comKey, 'com.');
        proofRecords = [
            nsec3Rec,
            new PacketResource(`${ownerLabel}.com.`, nsec3Sig, PacketClass.IN, 3600)
        ];
    }
    // proof === 'missing' → no records

    // Plain (unsigned) A record at host.unsigned.com.
    const unsignedA = new PacketResource('host.unsigned.com.', new A('192.0.2.10'), PacketClass.IN, 300);

    const counts = new Map<string, number>();

    const transport: RecursiveResolverTransport = async(serverIp, _port, query) => {
        counts.set(serverIp, (counts.get(serverIp) ?? 0) + 1);

        const q = query.questions[0];
        const qnameNorm = q.name.toLowerCase().replace(/\.$/u, '');
        const qtype = q.type;

        const reply = (
            answers: PacketResource[],
            rcode: number = 0,
            aa: boolean = true,
            authorities: PacketResource[] = [],
            additionals: PacketResource[] = []
        ): Packet => {
            const r = new Packet();
            r.header.id = query.header.id;
            r.header.qr = 1;
            r.header.aa = aa ? 1 : 0;
            r.header.rcode = rcode;
            r.questions = query.questions.slice();
            r.answers = answers;
            r.authorities = authorities;
            r.additionals = additionals;
            return r;
        };

        if (serverIp === '10.0.0.1') {
            if ((qnameNorm === '' || q.name === '.') && qtype === PacketTypes.DNSKEY) {
                return reply([
                    rootDnskeyRecord,
                    new PacketResource('.', rootDnskeySig, PacketClass.IN, 3600)
                ]);
            }

            if (qnameNorm === 'com' && qtype === PacketTypes.DS) {
                return reply([
                    dsComRec,
                    new PacketResource('com.', dsComSig, PacketClass.IN, 3600)
                ]);
            }

            return reply([], 0, false, [
                new PacketResource('com.', new NS('a.gtld.com.'), PacketClass.IN, 3600)
            ], [
                new PacketResource('a.gtld.com.', new A('10.0.0.2'), PacketClass.IN, 3600)
            ]);
        }

        if (serverIp === '10.0.0.2') {
            if (qnameNorm === 'com' && qtype === PacketTypes.DNSKEY) {
                return reply([
                    comDnskeyRecord,
                    new PacketResource('com.', comDnskeySig, PacketClass.IN, 3600)
                ]);
            }

            // The big case: DS query for the unsigned child.
            if (qnameNorm === 'unsigned.com' && qtype === PacketTypes.DS) {
                return reply([], 0, true, proofRecords);
            }

            // Anything under unsigned.com — referral to unsigned auth.
            return reply([], 0, false, [
                new PacketResource('unsigned.com.', new NS('ns.unsigned.com.'), PacketClass.IN, 3600)
            ], [
                new PacketResource('ns.unsigned.com.', new A('10.0.0.4'), PacketClass.IN, 3600)
            ]);
        }

        if (serverIp === '10.0.0.4') {
            if (qnameNorm === 'host.unsigned.com' && qtype === PacketTypes.A) {
                return reply([unsignedA]);
            }

            return reply([], RCODE.REFUSED);
        }

        throw new Error(`unknown server ${serverIp}`);
    };

    const resolver = new RecursiveResolver({
        transport: transport,
        rootHints: [{name: 'root.test.', ipv4: '10.0.0.1'}],
        use0x20: false,
        dnssec: {
            trustAnchors: [TrustAnchors.of('.', rootDs)],
            verifyOptions: {now: NOW_SEC}
        }
    });

    return {resolver: resolver, counts: counts};
};

test('RecursiveResolver#insecure delegation with NSEC proof passes through with AD=0', async() => {
    const {resolver} = buildInsecureUniverse('nsec');
    const r = await resolver.resolve('host.unsigned.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal((r.answers[0].packetType as A).address, '192.0.2.10');
    // eslint-disable-next-line no-bitwise
    assert.equal((r.header.z & 0b010) >> 1, 0, 'AD bit must be clear for an insecure answer');
});

test('RecursiveResolver#insecure delegation with NSEC3 opt-out cover passes through with AD=0', async() => {
    const {resolver} = buildInsecureUniverse('nsec3-optout');
    const r = await resolver.resolve('host.unsigned.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal((r.answers[0].packetType as A).address, '192.0.2.10');
    // eslint-disable-next-line no-bitwise
    assert.equal((r.header.z & 0b010) >> 1, 0);
});

test('RecursiveResolver#empty DS answer without proof is rejected as SERVFAIL', async() => {
    const {resolver} = buildInsecureUniverse('missing');
    const r = await resolver.resolve('host.unsigned.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.SERVFAIL,
        'a forged empty DS answer must not downgrade a signed zone');
});

test('RecursiveResolver#strict mode SERVFAILs even on properly-proven insecure delegations', async() => {
    // Same NSEC-proof universe but configure strict mode.
    const rootKey = csk();
    const comKey = csk();

    const dsCom = new DS(
        Dnssec.computeKeyTag(comKey.dnskey),
        comKey.dnskey.algorithm,
        DnssecDigest.SHA256,
        Dnssec.computeDsDigest('com.', comKey.dnskey, DnssecDigest.SHA256)
    );

    const rootDs = new DS(
        Dnssec.computeKeyTag(rootKey.dnskey),
        rootKey.dnskey.algorithm,
        DnssecDigest.SHA256,
        Dnssec.computeDsDigest('.', rootKey.dnskey, DnssecDigest.SHA256)
    );

    const rootDnskeyRecord = new PacketResource('.', rootKey.dnskey, PacketClass.IN, 3600);
    const comDnskeyRecord = new PacketResource('com.', comKey.dnskey, PacketClass.IN, 3600);

    const rootDnskeySig = signRrset('.', [rootDnskeyRecord], rootKey, '.');
    const comDnskeySig = signRrset('com.', [comDnskeyRecord], comKey, 'com.');

    const dsComRec = new PacketResource('com.', dsCom, PacketClass.IN, 3600);
    const dsComSig = signRrset('com.', [dsComRec], rootKey, '.');

    const nsecRec = new PacketResource(
        'unsigned.com.',
        new NSEC('zzz.com.', [PacketTypes.NS, PacketTypes.RRSIG, PacketTypes.NSEC]),
        PacketClass.IN, 3600
    );
    const nsecSig = signRrset('unsigned.com.', [nsecRec], comKey, 'com.');

    const unsignedA = new PacketResource('host.unsigned.com.', new A('192.0.2.10'), PacketClass.IN, 300);

    const transport: RecursiveResolverTransport = async(serverIp, _port, query) => {
        const q = query.questions[0];
        const qnameNorm = q.name.toLowerCase().replace(/\.$/u, '');
        const qtype = q.type;

        const reply = (
            answers: PacketResource[],
            rcode: number = 0,
            aa: boolean = true,
            authorities: PacketResource[] = [],
            additionals: PacketResource[] = []
        ): Packet => {
            const r = new Packet();
            r.header.id = query.header.id;
            r.header.qr = 1;
            r.header.aa = aa ? 1 : 0;
            r.header.rcode = rcode;
            r.questions = query.questions.slice();
            r.answers = answers;
            r.authorities = authorities;
            r.additionals = additionals;
            return r;
        };

        if (serverIp === '10.0.0.1') {
            if ((qnameNorm === '' || q.name === '.') && qtype === PacketTypes.DNSKEY) {
                return reply([
                    rootDnskeyRecord,
                    new PacketResource('.', rootDnskeySig, PacketClass.IN, 3600)
                ]);
            }

            if (qnameNorm === 'com' && qtype === PacketTypes.DS) {
                return reply([
                    dsComRec,
                    new PacketResource('com.', dsComSig, PacketClass.IN, 3600)
                ]);
            }

            return reply([], 0, false, [
                new PacketResource('com.', new NS('a.gtld.com.'), PacketClass.IN, 3600)
            ], [
                new PacketResource('a.gtld.com.', new A('10.0.0.2'), PacketClass.IN, 3600)
            ]);
        }

        if (serverIp === '10.0.0.2') {
            if (qnameNorm === 'com' && qtype === PacketTypes.DNSKEY) {
                return reply([
                    comDnskeyRecord,
                    new PacketResource('com.', comDnskeySig, PacketClass.IN, 3600)
                ]);
            }

            if (qnameNorm === 'unsigned.com' && qtype === PacketTypes.DS) {
                return reply([], 0, true, [
                    nsecRec,
                    new PacketResource('unsigned.com.', nsecSig, PacketClass.IN, 3600)
                ]);
            }

            return reply([], 0, false, [
                new PacketResource('unsigned.com.', new NS('ns.unsigned.com.'), PacketClass.IN, 3600)
            ], [
                new PacketResource('ns.unsigned.com.', new A('10.0.0.4'), PacketClass.IN, 3600)
            ]);
        }

        if (serverIp === '10.0.0.4') {
            if (qnameNorm === 'host.unsigned.com' && qtype === PacketTypes.A) {
                return reply([unsignedA]);
            }

            return reply([], RCODE.REFUSED);
        }

        throw new Error(`unknown server ${serverIp}`);
    };

    const resolver = new RecursiveResolver({
        transport: transport,
        rootHints: [{name: 'root.test.', ipv4: '10.0.0.1'}],
        use0x20: false,
        dnssec: {
            trustAnchors: [TrustAnchors.of('.', rootDs)],
            mode: 'strict',
            verifyOptions: {now: NOW_SEC}
        }
    });

    const r = await resolver.resolve('host.unsigned.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.SERVFAIL,
        'strict mode rejects insecure delegations even when properly proven');
});