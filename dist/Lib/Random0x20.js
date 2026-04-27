import crypto from 'crypto';
export class Random0x20 {
    static scramble(name) {
        if (name.length === 0) {
            return name;
        }
        const random = crypto.randomBytes(name.length);
        let out = '';
        for (let i = 0; i < name.length; i++) {
            const c = name.charCodeAt(i);
            const isUpper = c >= 0x41 && c <= 0x5A;
            const isLower = c >= 0x61 && c <= 0x7A;
            if (!isUpper && !isLower) {
                out += name[i];
                continue;
            }
            const flipToUpper = (random[i] & 1) === 0;
            out += String.fromCharCode(flipToUpper ? c & 0xDF : c | 0x20);
        }
        return out;
    }
    static matches(sent, received) {
        return sent === received;
    }
}
//# sourceMappingURL=Random0x20.js.map