/**
 * DNS message OPCODE values (header bits 1-4 of byte 2 / bits 11..14 in
 * a big-endian view of the flags word). Each value tells the receiver
 * how to interpret the rest of the message.
 *
 * @docs https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
 */
export enum PacketOpcode {

    /**
     * Standard query — the regular `dig example.com A` flow.
     */
    QUERY = 0,

    /**
     * Inverse query (RFC 1035 §3.7.1, deprecated by RFC 3425).
     */
    IQUERY = 1,

    /**
     * Server status request (RFC 1035 §3.7.2). Rarely used in practice.
     */
    STATUS = 2,

    /**
     * Zone-change notification from primary to secondary (RFC 1996).
     * Question section names the zone (QTYPE=SOA, QCLASS=IN); the AA flag
     * is set on the request.
     */
    NOTIFY = 4,

    /**
     * Dynamic update (RFC 2136). Uses the question, prerequisite, update,
     * and additional sections — not yet supported as a built-in handler.
     */
    UPDATE = 5,

    /**
     * DNS Stateful Operations (RFC 8490). Not yet implemented.
     */
    DSO = 6
}