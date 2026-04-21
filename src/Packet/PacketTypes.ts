/**
 * Packet Types
 * @docs https://tools.ietf.org/html/rfc1035#section-3.2.2
 */
export enum PacketTypes {
    A = 0x01,
    NS = 0x02,
    MD = 0x03,
    MF = 0x04,
    CNAME = 0x05,
    SOA = 0x06,
    MB = 0x07,
    MG = 0x08,
    MR = 0x09,
    NULL = 0x0A,
    WKS = 0x0B,
    PTR = 0x0C,
    HINFO = 0x0D,
    MINFO = 0x0E,
    MX = 0x0F,
    TXT = 0x10,
    AAAA = 0x1C,
    SRV = 0x21,
    EDNS = 0x29,
    DNSKEY = 0x30,
    RRSIG = 0x2E,
    SPF = 0x63,
    AXFR = 0xFC,
    MAILB = 0xFD,
    MAILA = 0xFE,
    ANY = 0xFF,
    CAA = 0x101
}