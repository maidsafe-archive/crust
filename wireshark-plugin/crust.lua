-- crust lua wireshark heuristic dissector
-- Dissects any TCP packet looking like a crust packet
-- Run temporarily using wireshark -X lua_script:crust.lua
-- Once not crashing wireshark :), can be copied into plugins dir for auto loading

local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end

local dprint = function(...) print(table.concat({"Lua:", ...}," ")) end

local crust = Proto("crust","MaidSafe crust Protocol")

local header = ProtoField.new("Header", "crust.header", ftypes.BYTES)
local event_id = ProtoField.new("Event", "crust.event_id", ftypes.UINT8)

crust.fields = { header, event_id }

function crust.dissector(tvbuf,pktinfo,root)

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("CRUST")

    -- We want to check that the packet size is rational during dissection, so let's get the length of the
    -- packet buffer (Tvb).
    -- Because DNS has no additional payload data other than itself, and it rides on UDP without padding,
    -- we can use tvb:len() or tvb:reported_len() here; but I prefer tvb:reported_length_remaining() as it's safer.
    local pktlen = tvbuf:reported_length_remaining()

    -- We start by adding our protocol to the dissection display tree.
    -- A call to tree:add() returns the child created, so we can add more "under" it using that return value.
    -- The second argument is how much of the buffer/packet this added tree item covers/represents - in this
    -- case (DNS protocol) that's the remainder of the packet.
    local tree = root:add(dns, tvbuf:range(0,pktlen))

    if tvbuf:len() < 9 then
      return
    end

    -- header is 90 18 63 18 72 18 75 18 31
    if tvbuf:range(2, 1):uint() ~= 0x63 or tvbuf:range(4, 1):uint() ~= 0x72 or tvbuf:range(6, 1):uint() ~= 0x75 or tvbuf:range(8, 1):uint() ~= 0x31 then
      return
    end

    tree:add(header, tvbuf:range(0, 9))
    tree:add(event_id, tvbuf:range(9,1))

    -- tell wireshark how much of tvbuff we dissected
    return 10
end


local function heur_dissect_crust(tvbuf,pktinfo,root)

    if tvbuf:len() < 9 then
      return false
    end
    
    -- header is 90 18 63 18 72 18 75 18 31
    if tvbuf:range(2, 1):uint() ~= 0x63 or tvbuf:range(4, 1):uint() ~= 0x72 or tvbuf:range(6, 1):uint() ~= 0x75 or tvbuf:range(8, 1):uint() ~= 0x31 then
      return false
    end
    dprint("crust: true")

    -- ok, looks like it's ours, so go dissect it
    -- note: calling the dissector directly like this is new in 1.11.3
    -- also note that calling a Dissector object, as this does, means we don't
    -- get back the return value of the dissector function we created previously
    -- so it might be better to just call the function directly instead of doing
    -- this, but this script is used for testing and this tests the call() function
    crust.dissector(tvbuf,pktinfo,root)

    -- since this is over a transport protocol, such as UDP, we can set the
    -- conversation to make it sticky for our dissector, so that all future
    -- packets to/from the same address:port pair will just call our dissector
    -- function directly instead of this heuristic function
    -- this is a new attribute of pinfo in 1.11.3
    pktinfo.conversation = crust

    return true
end


crust:register_heuristic("tcp",heur_dissect_crust)
