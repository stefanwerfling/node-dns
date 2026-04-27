export var PacketOpcode;
(function (PacketOpcode) {
    PacketOpcode[PacketOpcode["QUERY"] = 0] = "QUERY";
    PacketOpcode[PacketOpcode["IQUERY"] = 1] = "IQUERY";
    PacketOpcode[PacketOpcode["STATUS"] = 2] = "STATUS";
    PacketOpcode[PacketOpcode["NOTIFY"] = 4] = "NOTIFY";
    PacketOpcode[PacketOpcode["UPDATE"] = 5] = "UPDATE";
    PacketOpcode[PacketOpcode["DSO"] = 6] = "DSO";
})(PacketOpcode || (PacketOpcode = {}));
//# sourceMappingURL=PacketOpcode.js.map