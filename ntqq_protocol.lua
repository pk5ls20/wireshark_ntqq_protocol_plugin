local tea = require("tea")
local zlib = require("zlib")

-- ref https://github.com/LagrangeDev/lagrange-python & https://github.com/LagrangeDev/LagrangeGo
local Reader = {}
Reader.__index = Reader

function Reader.new(data)
    assert(type(data) == "string", "Invalid data type: " .. type(data))
    return setmetatable({ buffer = data, pos = 1 }, Reader)
end

function Reader:read_u8()
    local val = self.buffer:byte(self.pos)
    self.pos = self.pos + 1
    return val
end

function Reader:read_u16()
    local val = 0
    for i = 0, 1 do
        val = val * 256 + self.buffer:byte(self.pos + i)
    end
    self.pos = self.pos + 2
    return val
end

function Reader:read_u32()
    local val = 0
    for i = 0, 3 do
        val = val * 256 + self.buffer:byte(self.pos + i)
    end
    self.pos = self.pos + 4
    return val
end

function Reader:read_u64()
    local val = 0
    for i = 0, 7 do
        val = (val * 256) + self.buffer:byte(self.pos + i)
    end
    self.pos = self.pos + 8
    return val
end

function Reader:read_i8()
    local val = self:read_u8()
    if val >= 0x80 then
        val = val - 0x100
    end
    return val
end

function Reader:read_i16()
    local val = self:read_u16()
    if val >= 0x8000 then
        val = val - 0x10000
    end
    return val
end

function Reader:read_i32()
    local val = self:read_u32()
    if val >= 0x80000000 then
        val = val - 0x100000000
    end
    return val
end

function Reader:read_i64()
    local val = self:read_u64()
    if val >= 0x8000000000000000 then
        val = val - 0x10000000000000000
    end
    return val
end

function Reader:read_struct(format)
    local values = {}
    for i = 1, #format do
        local f = format:sub(i, i)
        if f == 'I' then
            table.insert(values, self:read_u32())
        elseif f == 'i' then
            local val = self:read_i32()
            table.insert(values, val)
        end
    end
    return unpack(values)
end

function Reader:read_bytes(length)
    local bytes = self.buffer:sub(self.pos, self.pos + length - 1)
    self.pos = self.pos + length
    return bytes
end

function Reader:read_string(length)
    local str = self:read_bytes(length)
    return str
end

function Reader:read_bytes_with_length(prefix, with_prefix)
    local length
    if with_prefix then
        if prefix == "u8" then
            length = self:read_u8() - 1
        elseif prefix == "u16" then
            length = self:read_u16() - 2
        elseif prefix == "u32" then
            length = self:read_u32() - 4
        elseif prefix == "u64" then
            length = self:read_u64() - 8
        end
    else
        if prefix == "u8" then
            length = self:read_u8()
        elseif prefix == "u16" then
            length = self:read_u16()
        elseif prefix == "u32" then
            length = self:read_u32()
        elseif prefix == "u64" then
            length = self:read_u64()
        end
    end
    return self:read_bytes(length)
end

function Reader:read_string_with_length(prefix, with_prefix)
    local bytes = self:read_bytes_with_length(prefix, with_prefix)
    return bytes
end

function Reader:remaining()
    return #self.buffer - self.pos + 1
end

local function hex_to_bin(hexstr)
    return (hexstr:gsub('..', function(cc)
        return string.char(tonumber(cc, 16))
    end))
end

local function bin_to_hex(str)
    return (str:gsub('.', function(c)
        return string.format('%02x', string.byte(c))
    end))
end

-- global TCP protocol
local lost_segment = Field.new('tcp.analysis.lost_segment')

-- global NTQQ protocol
local ntqq_protocol = Proto("ntqq_protocol", "NTQQ Protocol")

ntqq_protocol.prefs.d2_key = Pref.string("Business_D2Key", "", "Business_D2Key") -- TODO: Fill in multiple d2keys and automatically select based on uin
ntqq_protocol.prefs.port = Pref.string("Uni Packet Port", "80,8080", "Port")  -- TODO: dynamic choice port

local package_type = ProtoField.string("ntqq_protocol.package_type", "package_type", base.NONE)

-- recv protocol
-- base
local r_packet_length = ProtoField.uint32("receive.raw_packet_length", "raw_packet_length", base.DEC)
-- header
local r_sso_resp_type = ProtoField.uint32("receive.sso_resp_type", "resp_type", base.DEC)
local r_sso_header_enc_flag = ProtoField.uint32("receive.sso_header_enc_flag", "enc_flag", base.DEC)
local r_sso_header_uin = ProtoField.string("receive.sso_header_uin", "uin", base.NONE)
-- packet
local r_sso_decrypt_packet = ProtoField.bytes("receive.sso_decrypt_packet", "sso_decrypt_packet", base.NONE)
local r_sso_packet_compress_type = ProtoField.uint32("receive.sso_packet_compress_type", "compress_type", base.DEC)
local r_sso_packet_seq = ProtoField.string("receive.sso_packet.seq", "seq", base.NONE)
local r_sso_packet_ret_code = ProtoField.string("receive.sso_packet.ret_code", "ret_code", base.NONE)
local r_sso_packet_session_id = ProtoField.bytes("receive.sso_packet.session_id", "session_id", base.NONE)
local r_sso_packet_extra = ProtoField.string("receive.sso_packet.extra", "extra", base.NONE)
local r_sso_packet_cmd = ProtoField.string("receive.sso_packet.cmd", "cmd", base.NONE)
local r_sso_packet_data = ProtoField.bytes("receive.sso_packet.data", "data", base.NONE)

local function parse_sso_packet(buffer, is_oicq_body)
    local reader = Reader.new(buffer)
    local head_len, seq, ret_code = reader:read_struct("Iii")
    local extra = reader:read_string_with_length("u32", true)
    local cmd = reader:read_string_with_length("u32", true)
    local session_id = reader:read_bytes_with_length("u32", true)

    local compress_type = reader:read_u32()
    reader:read_bytes_with_length("u32", false)

    local data = reader:read_bytes_with_length("u32", false)
    if compress_type == 0 then
    elseif compress_type == 1 then
        local inflate_stream = zlib.inflate()
        local decompressed_data, eof, bytes_in, bytes_out = inflate_stream(data)
        if not eof then
            error("Decompression did not reach the end of the data stream.")
        end
        data = decompressed_data
    elseif compress_type == 2 then
        data = string.sub(data, 5)
    end

    if is_oicq_body and string.find(cmd, "wtlogin.login") then
        -- TODO: decrypt oicq body
        error("decrypt oicq body not implemented")
    end

    return {
        compress_type = compress_type,
        seq = seq,
        ret_code = ret_code,
        session_id = session_id,
        extra = extra,
        cmd = cmd,
        data = data,
    }
end

local responseType = {
    [10] = "RequestTypeLogin",
    [11] = "RequestTypeSimple",
    [12] = "RequestTypeNT",
    [13] = "unknown",
}

local function pdu_impl(body_len, buffer, pinfo)
    -- print("body_len", body_len, "buffer_len()", buffer:len(), "pinfo.desegment_len", pinfo.desegment_len)
    if buffer:len() < body_len then
        pinfo.desegment_len = body_len - buffer:len()
        -- print("!!! SET desegment_len", pinfo.desegment_len)
        return
    elseif buffer:len() > body_len then
        -- print("!!! Processing current PDU")
        local remaining_buffer = buffer:range(body_len):tvb()
        pdu_impl(remaining_buffer:range(0, 4):uint(), remaining_buffer, pinfo)
        return
    else
        -- print("!!! Processing complete PDU")
    end
end


local function ntqq_protocol_uni_login_receive_dissector(buffer, pinfo, tree)
    local subtree = tree:add(ntqq_protocol, buffer())
    local reader = Reader.new(buffer:raw())
    subtree:add(package_type, "UniPacket")

    -- raw packet len
    local packet_len = reader:read_u32()
    subtree:add(r_packet_length, packet_len)
    if (lost_segment() == nil) then
        pdu_impl(packet_len, buffer, pinfo)
    end

    -- raw packet
    -- raw packet: sso header
    local raw_packet = reader:read_bytes(packet_len - 4)
    reader = Reader.new(raw_packet)
    local resp_type = reader:read_i32()
    local enc_flag = reader:read_u8()
    reader:read_u8()
    local uin_str = reader:read_string_with_length("u32", true)
    local uin = tonumber(uin_str)    
    local sso_header_tree = subtree:add("sso_header", ByteArray.tvb(ByteArray.new(bin_to_hex(raw_packet:sub(1, reader.pos))), "SSO Header")())
    sso_header_tree:add(r_sso_resp_type, resp_type)
    sso_header_tree:add(r_sso_header_enc_flag, enc_flag)
    sso_header_tree:add(r_sso_header_uin, uin)
    -- print("resp_type", resp_type, type(resp_type), responseType[resp_type])
    if not responseType[resp_type] then
        error("invalid packet type")
    end

    -- raw packet: sso packet
    local sso_enc_packet = reader:read_bytes(reader:remaining())
    local sso_packet_tree = subtree:add("sso_packet", ByteArray.tvb(ByteArray.new(bin_to_hex(sso_enc_packet)), "SSO Packet")())
    if ntqq_protocol.prefs.d2_key == "" then
        return
    end

    -- raw packet: sso packet: decrept
    local sso_dec_packet_tvb
    if enc_flag == 0 then
        sso_dec_packet_tvb = ByteArray.tvb(sso_enc_packet, "SSO Packet")
    elseif enc_flag == 1 then
        local sso_dec_packet = tea.decrypt_qq(hex_to_bin(ntqq_protocol.prefs.d2_key), sso_enc_packet)
        local sso_dec_packet_data = ByteArray.new(bin_to_hex(sso_dec_packet))
        sso_dec_packet_tvb = ByteArray.tvb(sso_dec_packet_data, "SSO Decrypted Packet")
    elseif enc_flag == 2 then
        local sso_dec_packet = tea.decrypt_qq(string.rep("\0", 16), sso_enc_packet)
        local sso_dec_packet_data = ByteArray.new(bin_to_hex(sso_dec_packet))
        sso_dec_packet_tvb = ByteArray.tvb(sso_dec_packet_data, "SSO Decrypted Packet")
    end
    sso_packet_tree:add(r_sso_decrypt_packet, sso_dec_packet_tvb())

    -- raw packet: sso packet: paste sso packet
    local pasted_frame = parse_sso_packet(sso_dec_packet_tvb():raw(), enc_flag == 2)
    sso_packet_tree:add(r_sso_packet_compress_type, pasted_frame.compress_type)
    sso_packet_tree:add(r_sso_packet_seq, pasted_frame.seq)
    sso_packet_tree:add(r_sso_packet_ret_code, pasted_frame.ret_code)
    sso_packet_tree:add(r_sso_packet_session_id, ByteArray.tvb(ByteArray.new(bin_to_hex(pasted_frame.session_id)), "session_id")())
    sso_packet_tree:add(r_sso_packet_extra, pasted_frame.extra)
    sso_packet_tree:add(r_sso_packet_cmd, pasted_frame.cmd)

    -- packet frame: sso packet: sso packet data
    -- TODO: add body dissectors
    sso_packet_tree:add(r_sso_packet_data, ByteArray.tvb(ByteArray.new(bin_to_hex(pasted_frame.data)), "SSO Decrypted Packet Data")()) --proto
end

-- send protocol
-- base
local s_packet_length = ProtoField.uint32("send.raw_packet_length", "raw_packet_length", base.DEC)
-- header
local s_sso_head_d2 = ProtoField.bytes("send.sso_head_d2", "d2", base.NONE)
local s_sso_head_uin = ProtoField.string("send.sso_head_uin", "uin", base.NONE)
-- packet
local s_sso_decrept_packet = ProtoField.bytes("send.sso_decrept_packet", "sso_decrept_packet", base.NONE)
local s_sso_packet_seq = ProtoField.uint32("send.sso_packet.sso_packet.seq", "seq", base.DEC)
local s_sso_packet_appid = ProtoField.uint32("send.sso_packet.sso_packet.appid", "appid", base.DEC)
local s_sso_packet_locale_id = ProtoField.uint32("send.sso_packet.sso_packet.locale_id", "locale_id", base.DEC)
local s_sso_packet_tgt = ProtoField.bytes("send.sso_packet.sso_packet.tgt", "tgt", base.NONE)
local s_sso_packet_cmd = ProtoField.string("send.sso_packet.sso_packet.cmd", "cmd", base.NONE)
local s_sso_packet_guid = ProtoField.bytes("send.sso_packet.sso_packet.guid", "guid", base.NONE)
local s_sso_packet_app_version = ProtoField.string("send.sso_packet.sso_packet.app_version", "app_version", base.NONE)
local s_sso_packet_head = ProtoField.bytes("send.sso_packet.sso_packet.head", "head", base.NONE)
-- packet: sso packet body
local s_sso_packet_data = ProtoField.bytes("send.sso_packet.sso_packet.data", "data", base.NONE)

local function ntqq_protocol_uni_login_send_dissector(buffer, pinfo, tree)
    local subtree = tree:add(ntqq_protocol, buffer())
    subtree:add(package_type, "UniPacket")
    local reader = Reader.new(buffer:raw())
    local body_len = reader:read_u32()
    subtree:add(s_packet_length, body_len)
    if (lost_segment() == nil) then
        pdu_impl(body_len, buffer, pinfo)
    end

    -- raw packet
    -- raw packet: sso header
    local raw_packet = reader:read_bytes(body_len - 4)
    reader = Reader.new(raw_packet)
    reader:read_u32()
    reader:read_u8()
    local d2 = reader:read_bytes_with_length("u32", true)
    reader:read_u8()
    local uin = reader:read_string_with_length("u32", true)
    local sso_header_tree = subtree:add("sso_header", ByteArray.tvb(ByteArray.new(bin_to_hex(raw_packet:sub(1, reader.pos))), "SSO Header")())
    sso_header_tree:add(s_sso_head_d2, ByteArray.tvb(ByteArray.new(bin_to_hex(d2)), "d2key")())
    sso_header_tree:add(s_sso_head_uin, uin)

    -- raw packet: sso packet
    local sso_enc_packet = reader:read_bytes(reader:remaining())
    local sso_packet_tree = subtree:add("sso_packet", ByteArray.tvb(ByteArray.new(bin_to_hex(sso_enc_packet)), "SSO Packet")())
    if ntqq_protocol.prefs.d2_key == "" then
        return
    end

    -- raw packet: sso packet: decrept
    local tea_key
    if d2 == '' then
        tea_key = "00000000000000000000000000000000"
    else 
        tea_key = ntqq_protocol.prefs.d2_key
    end
    local sso_dec_packet = tea.decrypt_qq(hex_to_bin(tea_key), sso_enc_packet)
    sso_packet_tree:add(s_sso_decrept_packet, ByteArray.tvb(ByteArray.new(bin_to_hex(sso_dec_packet)), "SSO Decrypted Packet")())

    local sso_packer_reader = Reader.new(sso_dec_packet)
    local sso_packet_header = sso_packer_reader:read_bytes_with_length("u32", true)
    local sso_packet_header_reader = Reader.new(sso_packet_header)
    local seq = sso_packet_header_reader:read_u32()
    sso_packet_tree:add(s_sso_packet_seq, seq)
    local appid = sso_packet_header_reader:read_u32()
    sso_packet_tree:add(s_sso_packet_appid, appid)
    local locale_id = sso_packet_header_reader:read_u32()
    sso_packet_tree:add(s_sso_packet_locale_id, locale_id)
    sso_packet_header_reader:read_bytes(12)
    local tgt = sso_packet_header_reader:read_bytes_with_length("u32", true)
    sso_packet_tree:add(s_sso_packet_tgt, ByteArray.tvb(ByteArray.new(bin_to_hex(tgt)), "tgt")())
    local cmd = sso_packet_header_reader:read_string_with_length("u32", true)
    sso_packet_tree:add(s_sso_packet_cmd, cmd)
    sso_packet_header_reader:read_bytes_with_length("u32", true)
    local guid = sso_packet_header_reader:read_bytes_with_length("u32", true)
    sso_packet_tree:add(s_sso_packet_guid, ByteArray.tvb(ByteArray.new(bin_to_hex(guid)), "guid")())
    sso_packet_header_reader:read_bytes_with_length("u32", true)
    local app_version = sso_packet_header_reader:read_string_with_length("u16", true)
    sso_packet_tree:add(s_sso_packet_app_version, app_version)
    local proto_head = sso_packet_header_reader:read_bytes_with_length("u32", true)
    sso_packet_tree:add(s_sso_packet_head, ByteArray.tvb(ByteArray.new(bin_to_hex(proto_head)), "head")()) --proto
    -- sso body
    local sso_body_data = sso_packer_reader:read_bytes_with_length("u32", true)
    sso_packet_tree:add(s_sso_packet_data, ByteArray.tvb(ByteArray.new(bin_to_hex(sso_body_data)), "SSO Packet Body")()) --proto
end

-- highway protocol
local h_head = ProtoField.bytes("highway.head", "head", base.NONE)
local h_body = ProtoField.bytes("highway.body", "body", base.NONE)

-- frame data structure ref:  https://github.com/LagrangeDev/LagrangeGo/blob/master/client/internal/highway/frame.go
-- frame head part
-- -- STX: 0x28(40) (1 byte)
-- -- head length (4 bytes)
-- -- body length (4 bytes)
-- frame head data part
-- frame body data part
-- frame ETX part: 0x29(41) (1 byte)
local function ntqq_protocol_tcp_highway_dissector(tvb, pinfo, tree)
    local reader = Reader.new(tvb:raw())
    local flag = reader:read_u8()
    local head_len = reader:read_u32()
    local body_len = reader:read_u32()
    if flag ~= 0x28 or head_len > 1500 then
        -- error("invalid packet length")  -- head larger than common MTU, invalid packet
        return
    end
    -- print("head_len", head_len, "body_len", body_len, "tvb:len()", tvb:len(), "all head=", tvb:range(0, 9):bytes():tohex())
    if (lost_segment() == nil) then
        pdu_impl(9 + head_len + body_len + 1, tvb, pinfo) 
    end
    local subtree = tree:add(ntqq_protocol, tvb())
    subtree:add(package_type, "HighwayPacket (TCP)")
    subtree:add(h_head, tvb:range(9, head_len), "HighwayPacket Head")
    subtree:add(h_body, tvb:range(9 + head_len, body_len), "HighwayPacket Body")
end

-- fields
ntqq_protocol.fields = {
    -- type
    package_type,
    -- uni & login send
    s_packet_length, s_sso_head_d2, s_sso_head_uin, 
    s_sso_decrept_packet,
    s_sso_packet_seq, s_sso_packet_appid, s_sso_packet_locale_id, s_sso_packet_tgt, s_sso_packet_cmd, s_sso_packet_guid, s_sso_packet_app_version, s_sso_packet_head,
    s_sso_packet_data,
    -- uni & login recv
    r_packet_length, r_sso_resp_type, r_sso_header_enc_flag, r_sso_header_uin, 
    r_sso_decrypt_packet, 
    r_sso_packet_compress_type, r_sso_packet_seq, r_sso_packet_ret_code, r_sso_packet_session_id, r_sso_packet_extra, r_sso_packet_cmd,
    r_sso_packet_data,
    -- highway packet
    h_head, h_body
}

local port_table = {}

-- add ports in port_table
for port in string.gmatch(ntqq_protocol.prefs.port, "%d+") do
    -- print("adding port", port)
    port_table[tonumber(port)] = true
end

-- Assume that the first packet you receive is always correct
-- TODO: Add another check method
local function simple_check_uni_pkt(tvb)
    return tvb:range(0, 4):uint() == tvb:len()
end

local function simple_check_highway_pkt(tvb)
    return tvb:range(0, 1):bytes():tohex() == "28" and tvb:range(1, 4):uint() < 1500 and tvb:len() > 9
end

local function heur_dissect_ntqq_tcp_protocol(tvb, pinfo, tree)
    -- print("heuristic_dissector called, tvb len=", tvb:len(), "packet_len=", except_uni_len)
    if simple_check_uni_pkt(tvb) or simple_check_highway_pkt(tvb) then
        pinfo.conversation = ntqq_protocol
        return true
    else
        return false
    end
end

local http_host_field = Field.new("http.host")
local http_uri_field = Field.new("http.request.uri")

local function heur_dissect_ntqq_http_protocol(tvb, pinfo, tree)
    local http_host = http_host_field()
    local http_uri = http_uri_field()
    if http_host and http_uri and tostring(http_uri):match("/cgi%-bin/httpconn%?htcmd=.-&uin=.-") then
        -- print("heuristic_dissector HTTP called, http_host=", http_host, "http_uri=", http_uri)
        local subtree = tree:add(ntqq_protocol, tvb())
        subtree:add(package_type, "HighwayPacket (HTTP)")
        pinfo.cols.protocol = ntqq_protocol.name
        pinfo.conversation = ntqq_protocol
        return true
    else
        return false
    end
end

function ntqq_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = ntqq_protocol.name
    -- TODO: Optimize the packet categorization method for packages
    if simple_check_highway_pkt(buffer) then
        ntqq_protocol_tcp_highway_dissector(buffer, pinfo, tree)
    else
        if port_table[pinfo.src_port] then
            ntqq_protocol_uni_login_receive_dissector(buffer, pinfo, tree)
        elseif port_table[pinfo.dst_port] then
            ntqq_protocol_uni_login_send_dissector(buffer, pinfo, tree)
        end
    end
end

ntqq_protocol:register_heuristic("tcp", heur_dissect_ntqq_tcp_protocol)
ntqq_protocol:register_heuristic("http", heur_dissect_ntqq_http_protocol)