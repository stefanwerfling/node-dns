import { Buffer } from 'buffer';
export class ProxyProtocolTcpReader {
    static readHeader(socket, bytesNeeded) {
        return new Promise((resolve, reject) => {
            const state = {
                chunks: [],
                total: 0,
                needed: null,
                finished: false
            };
            const drain = () => {
                let chunk;
                while ((chunk = socket.read()) !== null) {
                    state.chunks.push(chunk);
                    state.total += chunk.length;
                }
            };
            const merge = () => {
                if (state.chunks.length === 1) {
                    return state.chunks[0];
                }
                const merged = Buffer.concat(state.chunks, state.total);
                state.chunks = [merged];
                return merged;
            };
            const tryResult = () => {
                if (state.needed === null) {
                    state.needed = bytesNeeded(merge());
                }
                if (state.needed !== null && state.total >= state.needed) {
                    const merged = merge();
                    return {
                        header: merged.subarray(0, state.needed),
                        remainder: merged.subarray(state.needed)
                    };
                }
                return null;
            };
            const listeners = {
                onReadable: () => {
                },
                onError: () => {
                },
                onEnd: () => {
                }
            };
            const detach = () => {
                socket.off('readable', listeners.onReadable);
                socket.off('error', listeners.onError);
                socket.off('end', listeners.onEnd);
            };
            const settleOk = (result) => {
                if (state.finished) {
                    return;
                }
                state.finished = true;
                detach();
                resolve(result);
            };
            const settleErr = (err) => {
                if (state.finished) {
                    return;
                }
                state.finished = true;
                detach();
                reject(err instanceof Error ? err : new Error(String(err)));
            };
            listeners.onReadable = () => {
                drain();
                try {
                    const result = tryResult();
                    if (result) {
                        settleOk(result);
                    }
                }
                catch (err) {
                    settleErr(err);
                }
            };
            listeners.onError = (err) => {
                settleErr(err);
            };
            listeners.onEnd = () => {
                settleErr(new Error('PROXY: socket closed before header was complete'));
            };
            socket.on('readable', listeners.onReadable);
            socket.on('error', listeners.onError);
            socket.on('end', listeners.onEnd);
            listeners.onReadable();
        });
    }
}
//# sourceMappingURL=ProxyProtocolTcpReader.js.map