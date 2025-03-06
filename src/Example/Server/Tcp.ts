import {TCPServer} from '../../Server/TCPServer.js';

const server = new TCPServer();
server.on('request', (message, send) => {

});

server.listen(5333);