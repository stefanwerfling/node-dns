/**
 * Packet Class
 * @docs https://tools.ietf.org/html/rfc1035#section-3.2.4
 */
export enum PacketClass {
    IN = 0x01,
    CS = 0x02,
    CH = 0x03,
    HS = 0x04,
    /**
     * Used by DNS UPDATE (RFC 2136 §2.4–§2.5) to encode "must-not-exist"
     * prerequisites and "delete this exact RR" updates. Not a query class.
     */
    NONE = 0xFE,
    ANY = 0xFF
}