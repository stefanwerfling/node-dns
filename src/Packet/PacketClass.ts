/**
 * Packet Class
 * @docs https://tools.ietf.org/html/rfc1035#section-3.2.4
 */
export enum PacketClass {
    IN = 0x01,
    CS = 0x02,
    CH = 0x03,
    HS = 0x04,
    ANY = 0xFF
}