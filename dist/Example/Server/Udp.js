import { Packet } from '../../Packet/Packet.js';
import { A } from '../../Packet/Types/A.js';
import { UDPServer } from '../../Server/UDPServer.js';
const server = new UDPServer();
server.on('request', async (request, send) => {
    const response = Packet.createResponseFromRequest(request);
    const answer = Packet.createResourceFromQuestion(request.questions[0], new A('8.8.8.8'));
    response.answers.push(answer);
    await send(response);
});
server.on('request', (request) => {
    console.log(request.header.id, request.questions[0]);
});
await server.listen(5333);
//# sourceMappingURL=Udp.js.map