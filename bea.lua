-- Name: BEA Protocol Lua script 
-- Discription: Lua script for Wireshark to decode BEA protocol
-- Author: KXU
-- Date: 2021/9/28


-- You can change the port number here
PORT = 50020
-- You can change the protocol type here (To be implemented!)
PROTOCOL_TYPE = 0

-- Dissector BEA protocol
my_proto = Proto("BEA", "BEA protocol")

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
angle_resol = ProtoField.uint16("bea.resol", "Angle Resolution", base.DEC)
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
    angle_resol,
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
    local subtree = tree:add(my_proto, buffer(), "BEA protocol")
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
    head_st:add(angle_resol, buffer(offset,2))
    offset = offset + 2
    head_st:add(timestamp, buffer(offset,2))
    offset = offset + 2
    
    -- Payload part
    local size = buffer:len() - offset - 2
    if (pkt:uint() == 0) then
        payload_st:add(distance, buffer(offset, size)) -- distance only
    else
        size = size / 2
        payload_st:add(distance, buffer(offset, size)) -- distance
        offset = offset + size
        payload_st:add(intensity, buffer(offset, size)) -- intensity
    end

    -- CRC part
    crc_st:add(crc, buffer(buffer:len()-2,2))
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(PORT, my_proto)