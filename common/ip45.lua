-- IP45 protocol
-- wireshark -X lua_script:ip45.lua or add the script 
-- to your local script directory

ip45_proto = Proto("ip45","IP45 Protocol")

local next_header = ProtoField.string("ip45.nh","Next header")
local smark = ProtoField.uint8("ip45.smark", "Src Mark")
local dmark = ProtoField.uint8("ip45.dstmark","Dst Mark")
local padding = ProtoField.uint16("ip45.padding", "Padding")
local src_stack = ProtoField.string("ip45.sstack","Src IP45 stack")
local dst_stack = ProtoField.string("ip45.dstack", "Dst IP45 stack")
local sid = ProtoField.new("Session ID", "ip45.sid",ftypes.BYTES)

-- register protocol fields
ip45_proto.fields = { next_header, smark, dmark, padding, src_stack, dst_stack, sid }

-- function to dissect the protocol
function ip45_proto.dissector(buffer,pinfo,tree)
    local IP45_HEADER_LEN = 44
    pinfo.cols.protocol = "IP45"
    local subtree = tree:add(ip45_proto,buffer(0,IP45_HEADER_LEN),"IP45 Protocol")
    local nh = buffer(0,1):uint()
    -- get a dissector, that will parse the next header payload
    local dis = DissectorTable.get("ip.proto"):get_dissector(nh)
    subtree:add(next_header, buffer(0,1), string.format("%s (%d)", tostring(dis), nh))
    subtree:add(smark, buffer(1,1), buffer(1,1):bitfield(4,4))
    subtree:add(dmark, buffer(1,1), buffer(1,1):bitfield(0,4))
    subtree:add(padding, buffer(2,2))
    -- use ipv4 function to convert bytes, instead of iteration through the 12 bytes field
    local s1 = tostring(buffer(4,4):ipv4())
    local s2 = tostring(buffer(8,4):ipv4())
    local s3 = tostring(buffer(12,4):ipv4())
    local d1 = tostring(buffer(16,4):ipv4())
    local d2 = tostring(buffer(20,4):ipv4())
    local d3 = tostring(buffer(24,4):ipv4())
    subtree:add(src_stack, buffer(4,12), string.format("%s.%s.%s",s1,s2,s3))
    subtree:add(dst_stack, buffer(16,12), string.format("%s.%s.%s",d1,d2,d3))
    subtree:add(sid, buffer(28,16))
    dis:call(buffer(IP45_HEADER_LEN):tvb(), pinfo, tree)

end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register the ip45 protocol to handle udp port 4
udp_table:add(4,ip45_proto)
