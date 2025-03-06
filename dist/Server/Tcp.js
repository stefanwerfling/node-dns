"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Tcp = void 0;
const tslib_1 = require("tslib");
const net_1 = tslib_1.__importDefault(require("net"));
class Tcp extends net_1.default.Server {
    constructor(options) {
        super();
    }
}
exports.Tcp = Tcp;
//# sourceMappingURL=Tcp.js.map