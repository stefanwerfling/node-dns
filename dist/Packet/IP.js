export class IP {
    static toIPv6(buffer) {
        const str = buffer.map((part) => {
            return part > 0 ? part.toString(16) : '0';
        });
        return str.join(':').replace(/\b(?:0+:)+/u, ':');
    }
    static fromIPv6(address) {
        const digits = address.split(':');
        if (digits[0] === '') {
            digits.shift();
        }
        if (digits[digits.length - 1] === '') {
            digits.pop();
        }
        const missingFields = 8 - digits.length + 1;
        return digits.flatMap((digit) => {
            if (digit === '') {
                return Array(missingFields).fill('0');
            }
            return digit.padStart(4, '0');
        });
    }
}
//# sourceMappingURL=IP.js.map