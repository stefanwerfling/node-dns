"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ClientOptionsProtocol = void 0;
var ClientOptionsProtocol;
(function (ClientOptionsProtocol) {
    ClientOptionsProtocol[ClientOptionsProtocol["udp"] = 0] = "udp";
    ClientOptionsProtocol[ClientOptionsProtocol["tcp"] = 1] = "tcp";
    ClientOptionsProtocol[ClientOptionsProtocol["tls"] = 2] = "tls";
    ClientOptionsProtocol[ClientOptionsProtocol["doh"] = 3] = "doh";
    ClientOptionsProtocol[ClientOptionsProtocol["google"] = 4] = "google";
})(ClientOptionsProtocol || (exports.ClientOptionsProtocol = ClientOptionsProtocol = {}));
//# sourceMappingURL=ClientOptions.js.map