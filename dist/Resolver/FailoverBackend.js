import { RCODE } from './RecursiveResolver.js';
const defaultPredicate = (r) => {
    if (r instanceof Error) {
        return true;
    }
    return r.header.rcode === RCODE.SERVFAIL;
};
const withTimeout = (promise, timeoutMs, label) => {
    if (timeoutMs <= 0) {
        return promise;
    }
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error(`FailoverBackend: ${label} exceeded ${timeoutMs}ms`));
        }, timeoutMs);
        promise.then((v) => {
            clearTimeout(timer);
            resolve(v);
        }, (err) => {
            clearTimeout(timer);
            reject(err instanceof Error ? err : new Error(String(err)));
        });
    });
};
export class FailoverBackend {
    static combine(backends, options = {}) {
        if (backends.length === 0) {
            throw new Error('FailoverBackend.combine: at least one backend is required');
        }
        const timeoutMs = options.timeoutMs ?? 5000;
        const attempts = Math.max(1, options.attempts ?? 2);
        const rotate = options.rotate === true;
        const shouldFailover = options.shouldFailover ?? defaultPredicate;
        let rotationCursor = 0;
        return async (name, type, cls) => {
            const start = rotate ? rotationCursor++ % backends.length : 0;
            let lastError = null;
            let lastPacket = null;
            for (let i = 0; i < backends.length; i++) {
                const backendIdx = (start + i) % backends.length;
                const backend = backends[backendIdx];
                for (let attempt = 0; attempt < attempts; attempt++) {
                    let outcome;
                    try {
                        outcome = await withTimeout(backend(name, type, cls), timeoutMs, `backend ${backendIdx} attempt ${attempt + 1}`);
                    }
                    catch (err) {
                        outcome = err instanceof Error ? err : new Error(String(err));
                    }
                    if (outcome instanceof Error) {
                        lastError = outcome;
                        lastPacket = null;
                    }
                    else {
                        lastPacket = outcome;
                        lastError = null;
                    }
                    if (!shouldFailover(outcome)) {
                        return outcome;
                    }
                }
            }
            if (lastPacket !== null) {
                return lastPacket;
            }
            throw lastError ?? new Error('FailoverBackend: exhausted with no outcome');
        };
    }
    static fromConfig(parsed, builder, options = {}) {
        if (parsed.nameservers.length === 0) {
            return null;
        }
        const backends = parsed.nameservers.map((host) => builder({ host: host }));
        const timeoutMs = parsed.options.timeout !== undefined
            ? parsed.options.timeout * 1000
            : undefined;
        return FailoverBackend.combine(backends, {
            timeoutMs: timeoutMs,
            attempts: parsed.options.attempts,
            rotate: parsed.options.rotate,
            shouldFailover: options.shouldFailover
        });
    }
    static defaultShouldFailover = defaultPredicate;
}
//# sourceMappingURL=FailoverBackend.js.map