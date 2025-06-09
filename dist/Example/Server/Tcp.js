import { Packet } from '../../Packet/Packet.js';
import { SRV } from '../../Packet/Types/SRV.js';
import { TCPServer } from '../../Server/TCPServer.js';
const server = new TCPServer();
server.on('request', (request, send) => {
    const response = Packet.createResponseFromRequest(request);
    const answer = Packet.createResourceFromQuestion(request.questions[0], new SRV(30, 30, 8080, 'hermes2.jabber.org'));
    response.answers.push(answer);
    send(response);
});
server.listen(5333);
//# sourceMappingURL=Tcp.js.map