export class IP {

    public static toIPv6(buffer: number[]): string {
        const str = buffer.map((part) => {
            return part > 0 ? part.toString(16) : '0';
        });

        return str.join(':').replace(/\b(?:0+:)+/u, ':');
    }

}