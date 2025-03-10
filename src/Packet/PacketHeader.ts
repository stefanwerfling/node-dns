import {BufferReader} from '../Lib/BufferReader.js';
import {BufferWriter} from '../Lib/BufferWriter.js';

/**
 * @docs https://tools.ietf.org/html/rfc1035#section-4.1.1
 */
export class PacketHeader {

    /**
     * A 16-bit identifier assigned by the program that
     * generates any kind of query.  This identifier is copied
     * the corresponding reply and can be used by the requester
     * to match up replies to outstanding queries.
     */
    public id: number = 0;

    /**
     * A one bit field that specifies whether this message is a
     * query (0), or a response (1).
     */
    public qr: number = 0;

    /**
     * A four-bit field that specifies kind of query in this
     * message.  This value is set by the originator of a query
     * and copied into the response.  The values are:
     *
     * 0 - a standard query (QUERY)
     * 1 - an inverse query (IQUERY)
     * 2 - a server status request (STATUS)
     * 3-15 - reserved for future use
     */
    public opcode: number = 0;

    /**
     * Authoritative Answer - this bit is valid in responses,
     * and specifies that the responding name server is an
     * authority for the domain name in question section.
     *
     * Note that the contents of the answer section may have
     * multiple owner names because of aliases. The AA bit
     * corresponds to the name which matches the query name, or
     * the first owner name in the answer section.
     */
    public aa: number = 0;

    /**
     * TrunCation - specifies that this message was truncated
     * due to length greater than that permitted on the
     * transmission channel.
     */
    public tc: number = 0;

    /**
     * Recursion Desired - this bit may be set in a query and
     * is copied into the response.  If RD is set, it directs
     * the name server to pursue the query recursively.
     * Recursive query support is optional.
     */
    public rd: number = 0;

    /**
     * Recursion Available - this be is set or cleared in a
     * response, and denotes whether recursive query support is
     * available in the name server.
     */
    public ra: number = 0;

    /**
     * Reserved for future use.  Must be zero in all queries
     * and responses.
     */
    public z: number = 0;

    /**
     * Response code - this 4 bit field is set as part of
     * responses.  The values have the following
     * interpretation:
     *
     * 0 - No error condition
     * 1 - Format error - The name server was unable to interpret the query.
     * 2 - Server failure - The name server was unable to process this query due to a problem with the name server.
     * 3 - Name Error - Meaningful only for responses from an authoritative name server,
     *      this code signifies that the domain name referenced in the query does not exist.
     * 4 - Not Implemented - The name server does not support the requested kind of query.
     * 5 - Refused - The name server refuses to perform the specified operation for
     *      policy reasons.  For example, a name server may not wish to provide the
     *      information to the particular requester, or a name server may not wish to perform
     *      a particular operation (e.g., zone transfer) for particular data.
 *     6-15 - Reserved for future use.
     */
    public rcode: number = 0;

    /**
     * QDCOUNT an unsigned 16 bit integer specifying the number of entries in the question section.
     */
    public qdcount: number = 0;

    /**
     * ANCOUNT an unsigned 16 bit integer specifying the number of resource records in the answer section.
     */
    public ancount: number = 0;

    /**
     * NSCOUNT an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
     */
    public nscount: number = 0;

    /**
     * ARCOUNT an unsigned 16 bit integer specifying the number of resource records in the additional records section.
     */
    public arcount: number = 0;

    /**
     * Parse
     * @param {BufferReader|Buffer} reader
     * @return {PacketHeader}
     */
    public static parse(reader: BufferReader|Buffer): PacketHeader {
        const tReader = reader instanceof BufferReader ? reader : new BufferReader(reader);

        const header = new PacketHeader();
        header.id = tReader.read(16);
        header.qr = tReader.read(1);
        header.opcode = tReader.read(4);
        header.aa = tReader.read(1);
        header.tc = tReader.read(1);
        header.rd = tReader.read(1);
        header.ra = tReader.read(1);
        header.z = tReader.read(3);
        header.rcode = tReader.read(4);
        header.qdcount = tReader.read(16);
        header.ancount = tReader.read(16);
        header.nscount = tReader.read(16);
        header.arcount = tReader.read(16);

        return header;
    }

    /**
     * Convert Header to Buffer
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public toBuffer(writer: BufferWriter|null = null): Buffer {
        const tWriter = writer === null ? new BufferWriter() : writer;

        tWriter.write(this.id, 16);
        tWriter.write(this.qr, 1);
        tWriter.write(this.opcode, 4);
        tWriter.write(this.aa, 1);
        tWriter.write(this.tc, 1);
        tWriter.write(this.rd, 1);
        tWriter.write(this.ra, 1);
        tWriter.write(this.z, 3);
        tWriter.write(this.rcode, 4);
        tWriter.write(this.qdcount, 16);
        tWriter.write(this.ancount, 16);
        tWriter.write(this.nscount, 16);
        tWriter.write(this.arcount, 16);

        return tWriter.toBuffer();
    }

}