import crypto from 'crypto';

/**
 * "0x20" query-name case randomization.
 *
 * DNS names are case-insensitive at the protocol level (RFC 1035 §2.3.3),
 * but the on-wire bytes preserve whichever case the sender used. A
 * recursor or authoritative server is expected to copy the question name
 * back into the response verbatim — including its case.
 *
 * The "0x20 hack" (Vixie, 2008; later RFC 5452 §9.2) exploits that
 * property: a stub randomizes the case of the QNAME before sending, then
 * compares the received question name **case-sensitively** to what it
 * sent. A successful spoof would have to guess not just the 16-bit
 * transaction ID and source port but also the exact case pattern of every
 * letter in the name — substantially raising the bar against off-path
 * attackers.
 *
 * Only ASCII letters [A-Za-z] are flipped — all other bytes (digits,
 * hyphens, dots, IDN punycode, escape sequences) are passed through.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc5452#section-9.2
 */
export class Random0x20 {

    /**
     * Return a copy of `name` with each ASCII letter independently flipped
     * to upper or lower case with 50% probability, drawn from the OS CSPRNG.
     */
    public static scramble(name: string): string {
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

            // eslint-disable-next-line no-bitwise
            const flipToUpper = (random[i] & 1) === 0;
            out += String.fromCharCode(flipToUpper ? c & 0xDF : c | 0x20);
        }

        return out;
    }

    /**
     * Case-sensitive string comparison used to verify that the response
     * echoed back the same case the query carried. Both arguments are
     * compared as-is (no Unicode normalization, no trailing-dot trimming
     * — names should already be in canonical form when this is called).
     */
    public static matches(sent: string, received: string): boolean {
        return sent === received;
    }

}