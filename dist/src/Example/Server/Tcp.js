"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Packet_js_1 = require("../../Packet/Packet.js");
const SRV_js_1 = require("../../Packet/Types/SRV.js");
const TCPServer_js_1 = require("../../Server/TCPServer.js");
const server = new TCPServer_js_1.TCPServer();
server.on('request', (request, send) => {
    const response = Packet_js_1.Packet.createResponseFromRequest(request);
    const answer = Packet_js_1.Packet.createResourceFromQuestion(request.questions[0], new SRV_js_1.SRV(30, 30, 8080, 'hermes2.jabber.org'));
    response.answers.push(answer);
    send(response);
});
server.listen(5333);
//# sourceMappingURL=Tcp.js.map