import { Buffer } from 'buffer';
export var TsigAlgorithm;
(function (TsigAlgorithm) {
    TsigAlgorithm["HMAC_MD5"] = "hmac-md5.sig-alg.reg.int.";
    TsigAlgorithm["HMAC_SHA1"] = "hmac-sha1.";
    TsigAlgorithm["HMAC_SHA224"] = "hmac-sha224.";
    TsigAlgorithm["HMAC_SHA256"] = "hmac-sha256.";
    TsigAlgorithm["HMAC_SHA384"] = "hmac-sha384.";
    TsigAlgorithm["HMAC_SHA512"] = "hmac-sha512.";
})(TsigAlgorithm || (TsigAlgorithm = {}));
export class TsigKey {
    name;
    algorithm;
    secret;
    constructor(name, algorithm, secret) {
        this.name = name;
        this.algorithm = algorithm;
        this.secret = typeof secret === 'string' ? Buffer.from(secret, 'base64') : secret;
    }
}
//# sourceMappingURL=TsigKey.js.map