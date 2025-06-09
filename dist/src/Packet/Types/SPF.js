"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SPF = void 0;
const PacketTypes_js_1 = require("../PacketTypes.js");
const TXT_js_1 = require("./TXT.js");
class SPF extends TXT_js_1.TXT {
    constructor(data = '') {
        super(data, PacketTypes_js_1.PacketTypes.SPF);
    }
}
exports.SPF = SPF;
//# sourceMappingURL=SPF.js.map