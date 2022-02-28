-- CS168 RIP Protocol Dissector
--
-- The structure of a RIP message is as follows:
-- uint16_t command
-- uint16_t num_entries
-- struct {
--     uint32_t cost
--     uint32_t address
-- } entries[num_entries]

local RIP_HEADER_LEN = 4
local ROUTE_ENTRY_LEN = 12

rip_protocol = Proto("CS168RIP",  "CS168 RIP")

command = ProtoField.uint16("cs168rip.command", "command", base.DEC)
num_entries = ProtoField.uint16("cs168rip.num_entries", "num_entries", base.DEC)

rip_entry_cost = ProtoField.uint32("cs168rip.entry.cost", "cost", base.DEC)
rip_entry_addr = ProtoField.ipv4("cs168rip.entry.address", "address")
rip_entry_mask = ProtoField.ipv4("cs168rip.entry.mask", "mask")


rip_protocol.fields = {
  command,
  num_entries,
  rip_entry_cost,
  rip_entry_addr,
  rip_entry_mask,
}

local ef_bad_entry = ProtoExpert.new("cs168rip.query.entry.expert",
                                     "Route entry missing or malformed",
                                     expert.group.MALFORMED,
                                     expert.severity.WARN)

rip_protocol.experts = {
  ef_bad_entry,
}

local field_cost = Field.new("cs168rip.entry.cost")
local field_addr = Field.new("cs168rip.entry.address")
local field_mask = Field.new("cs168rip.entry.mask")


function rip_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
    if length == 0 then return end

  pinfo.cols.protocol = rip_protocol.name

  local subtree = tree:add(rip_protocol, buffer(), "CS168 RIP Protocol")

  local pktlen = buffer:reported_length_remaining()

  local cmd_num = buffer(0, 2):uint()
  local cmd_name = get_command_name(cmd_num)

  -- Add command ID and name
  subtree:add(command, buffer(0, 2)):append_text(" (" .. cmd_name .. ") ")
  pinfo.cols.info:append("RIP " .. cmd_name)

  -- num_entries
  local entry_count = buffer(2, 2):uint()
  subtree:add(num_entries, buffer(2, 2))
  pinfo.cols.info:append(" (" .. entry_count .. " entries)")

  local pos = RIP_HEADER_LEN
  local e_idx = 0

  -- Parse each entry
  if entry_count > 0 then
    local entry_tree = subtree:add("Entries")

    local pkt_remaining = pktlen - pos

    while entry_count > 0 and pkt_remaining > 0 do
      if pkt_remaining < ROUTE_ENTRY_LEN then
        entry_tree:add_proto_expert_info(ef_bad_entry)
        return
      end

      local cost = buffer(pos, 4):uint()
      local address = buffer(pos + 4, 4):uint()
      local mask = buffer(pos + 8, 4):uint()

      -- TODO Add each entry to its own subtree (with helpful summary)
      local etree = entry_tree

      etree:add(rip_entry_cost, buffer(pos, 4))
      etree:add(rip_entry_addr, buffer(pos + 4, 4))
      etree:add(rip_entry_mask, buffer(pos + 8, 4))

      pos = pos + 12

      pkt_remaining = pkt_remaining - 12
      entry_count = entry_count - 1
      e_idx = e_idx + 1
    end
  end

end

function get_command_name(cmd)
  local name = "UNKNOWN"
  if cmd == 1 then name = "REQUEST"
  elseif cmd == 2 then name = "RESPONSE"
  end

  return name
end


local ip_proto = DissectorTable.get("ip.proto")
ip_proto:add(200, rip_protocol.dissector)
