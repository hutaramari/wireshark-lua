-- Name: BEA Protocol Lua script 
-- Discription: Lua script for Wireshark to decode BEA protocol
-- Author: KXU
-- Date: 2021/9/28


-- You can change the port number here
PORT = 3050
-- You can change the protocol type here (To be implemented!)
PROTOCOL_TYPE = 0

-- Define the menu for entry's cb
local function dialog_menu()
    local function dialog_func(prototype, port)
        local window = TextWindow.new("Network info");
        local msg = string.format("Protocol=%s, Port=%d", prototype, port)
        window:set(msg)
        -- PROTOCOL_TYPE = prototype
        -- PORT = port
    end
    new_dialog("Dialog", dialog_func, "Proto", "Port")
end
-- Create entry
register_menu("Lua BEA", dialog_menu, MENU_TOOLS_UNSORTED)
--if gui_enabled() then
--    local splash = TextWindow.new("Hello");
--    splash:set("Wish has enhance with a unsless.\n")
--    splash:append("goto tools->test and check it out")
--end

-- Dissector BEA MDI protocol
my_proto = Proto("BEA_MDI", "BEA MDI protocol")

sync = ProtoField.uint32("bea.sync", "SYNC", base.HEX)
packet_type = ProtoField.uint8("bea.packet_type", "Packet Type", base.DEC)
packet_size = ProtoField.uint16("bea.packet_size", "Packet Length", base.DEC)
resv = ProtoField.uint64("bea.resv", "Reserved", base.DEC)
packet_num = ProtoField.uint16("bea.packet_num", "Packet Number", base.DEC)
total_num = ProtoField.uint8("bea.total_num", "Total Number", base.DEC)
sub_num = ProtoField.uint8("bea.sub_num", "Sub Number", base.DEC)
freq = ProtoField.uint16("bea.freq", "Frequency", base.DEC)
points = ProtoField.uint16("bea.points","Spots Number", base.DEC)
first_angle = ProtoField.int16("bea.first_angle", "First Angle",base.DEC)
delta_angle = ProtoField.int16("bea.resol", "Delta Angle", base.DEC)
timestamp = ProtoField.uint16("bea.timestamp", "Timestamp", base.HEX)
data = ProtoField.none("bea.data", "Data", base.UNICODE)
distance = ProtoField.none("bea.distance", "Distance", base.UNICODE)
intensity = ProtoField.none("bea.intensity", "Intensity", base.UNICODE)
crc = ProtoField.uint16("bea.crc", "CRC", base.HEX)

my_proto.fields = {
    sync,
    packet_type,
    packet_size,
    resv,
    packet_num,
    total_num,
    sub_num,
    freq,
    points,
    first_angle,
    delta_angle,
    timestamp,
    distance,
    intensity,
    crc
}

-- Dissector callback function
function my_proto.dissector(buffer, pinfo, tree)
    if buffer:len() < 27 then return end
    local idendifier = buffer(0,4)
    if idendifier:uint() ~= 0xBEA01234 then return end

    pinfo.cols.protocol = my_proto.name

    -- BEA protocol decoding tree
    local subtree = tree:add(my_proto, buffer(), "BEA MDI protocol")
    -- Divide into 3 parts
    local head_st = subtree:add(my_proto, buffer(0, 27), "Header")
    local payload_st = subtree:add(my_proto, buffer(27, buffer:len()-27-2), "MDI")
    local crc_st = subtree:add(my_proto, buffer(buffer:len()-2,2), "CRC")
    
    -- Header part
    local offset = 0
    head_st:add(sync, buffer(offset,4))
    offset = offset + 4
    ---- Decode packet type
    local pkt = buffer(offset, 1)
    if (pkt:uint() == 0) then
        head_st:add(packet_type, pkt):append_text(" (Distance Only)")
    else
        head_st:add(packet_type, pkt):append_text(" (Distance and Intensity)")
    end
    offset = offset + 1
    head_st:add(packet_size, buffer(offset,2))
    offset = offset + 2
    head_st:add(resv, buffer(offset,6))
    offset = offset + 6
    head_st:add(packet_num, buffer(offset,2))
    offset = offset + 2
    head_st:add(total_num, buffer(offset,1))
    offset = offset + 1
    head_st:add(sub_num, buffer(offset,1))
    offset = offset + 1
    head_st:add(freq, buffer(offset,2))
    offset = offset + 2
    head_st:add(points, buffer(offset,2))
    offset = offset + 2
    head_st:add(first_angle, buffer(offset,2))
    offset = offset + 2
    head_st:add(delta_angle, buffer(offset,2))
    offset = offset + 2
    head_st:add(timestamp, buffer(offset,2))
    offset = offset + 2
    
    -- Payload part
    local size = buffer:len() - offset - 2
    if (pkt:uint() == 0) then
        payload_st:add(distance, buffer(offset, size)):append_text(string.format(" (%d spots)", size/2)) -- distance only
    else
        size = size / 2
        payload_st:add(distance, buffer(offset, size)):append_text(string.format(" (%d spots)", size/2)) -- distance
        offset = offset + size
        payload_st:add(intensity, buffer(offset, size)):append_text(string.format(" (%d spots)", size/2)) -- intensity
    end

    -- CRC part
    crc_st:add(crc, buffer(buffer:len()-2,2))
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(PORT, my_proto)


-- Dissector BEA Request Command Protocol (TCP)
my_tcp_proto_asc = Proto("BEA_ASC", "BEA ASC protocol")
my_tcp_proto_bin = Proto("BEA_BIN", "BEA BIN protocol")

cmdSyncBin = ProtoField.uint64("bea.sync",   "SYNC",     base.HEX)
cmdLenBin  = ProtoField.uint16("bea.cmdLen", "Length",   base.DEC)
cmdDataBin = ProtoField.none("bea.command",  "Command",  base.UNICODE)
cmdChkBin  = ProtoField.uint8("bea.chksum",  "Checksum", base.HEX)


cmdSyncAsc = ProtoField.uint8("bea.sync",    "SYNC",     base.HEX)
cmdDataAsc = ProtoField.none("bea.command",  "Command",  base.UNICODE)
cmdFootAsc = ProtoField.uint8("bea.footer",  "End",      base.HEX)

my_tcp_proto_asc.fields = {
    cmdSyncAsc,
    cmdDataAsc,
    cmdFootAsc
}
my_tcp_proto_bin.fields = {
    cmdSyncBin,
    cmdLenBin,
    cmdDataBin,
    cmdChkBin
}

-- Dissector cb function for ASC protocol
function my_tcp_proto_asc.dissector(buffer, pinfo, tree)
    if buffer:len() < 2 then return end
    local idendifier1 = buffer(0,1)
    local idendifier2 = buffer(buffer:len()-1,1)
    if idendifier1:uint() ~= 0x02 then return end
    if idendifier2:uint() ~= 0x03 then return end

    pinfo.cols.protocol = my_tcp_proto_asc.name

    local subtree = tree:add(my_tcp_proto_asc, buffer(), "BEA ASC protocol")
    local head_st = subtree:add(my_tcp_proto_asc, buffer(0,1), "STX")
    local payload_st = subtree:add(my_tcp_proto_asc, buffer(1, buffer:len()-2), "Command")
    local end_st = subtree:add(my_tcp_proto_asc, buffer(buffer:len()-1, 1), "ETX")

    head_st:add(cmdSyncAsc, buffer(0,1))
    payload_st:add(cmdDataAsc, buffer(1, buffer:len()-2)):append_text(string.format("=%s", buffer(1,buffer:len()-2):string()))
    end_st:add(cmdFootAsc, buffer(buffer:len()-1,1))

end

function my_tcp_proto_bin.dissector(buffer, pinfo, tree)
    if buffer:len() < 9 then return end
    local idendifier = buffer(0,6)
    if idendifier:uint64() ~= 0x0202BEA01234 then return end

    pinfo.cols.protocol = my_tcp_proto_bin.name
    
    local subtree    = tree:add(my_tcp_proto_bin, buffer(), "BEA BIN protocol")
    local head_st    = subtree:add(my_tcp_proto_bin, buffer(0,8), "Header")
    local payload_st = subtree:add(my_tcp_proto_bin, buffer(8, buffer:len()-9), "Command")
    local chk_st     = subtree:add(my_tcp_proto_bin, buffer(buffer:len()-1,1),"Checksum")

    head_st:add(cmdSyncBin, buffer(0,6))
    head_st:add(cmdLenBin, buffer(6,2))
    payload_st:add(cmdDataBin, buffer(8, buffer:len()-9))
    chk_st:add(cmdChkBin, buffer(buffer:len()-1, 1))
    
end

local tcp_port = DissectorTable.get("tcp.port")
if PROTOCOL_TYPE == 0 then
    tcp_port:add(PORT, my_tcp_proto_asc)
else
    tcp_port:add(PORT, my_tcp_proto_bin)
end
