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

ntqq_protocol.prefs.d2_key = Pref.string("Business_D2Key", "", "Business_D2Key")
ntqq_protocol.prefs.port = Pref.uint("Port", 8080, "Port")

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
    RequestTypeLogin = 10,
    RequestTypeSimple = 11,
    RequestTypeNT = 12
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


local function ntqq_protocol_recv_dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = ntqq_protocol.name
    local subtree = tree:add(ntqq_protocol, buffer())
    local reader = Reader.new(buffer:raw())

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
    if resp_type ~= responseType.RequestTypeLogin and resp_type ~= responseType.RequestTypeSimple and resp_type ~= responseType.RequestTypeNT then
        error("invalid packet type")
    end

    -- raw packet: sso packet
    local sso_enc_packet = reader:read_bytes(reader:remaining())
    local sso_packet_tree = subtree:add("sso_packet", ByteArray.tvb(ByteArray.new(bin_to_hex(sso_enc_packet)), "SSO Packet")())

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

local function ntqq_protocol_send_dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = ntqq_protocol.name
    local subtree = tree:add(ntqq_protocol, buffer())
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

    -- raw packet: sso packet: decrept
    local sso_dec_packet = tea.decrypt_qq(hex_to_bin(ntqq_protocol.prefs.d2_key), sso_enc_packet)
    sso_packet_tree:add(s_sso_decrept_packet, ByteArray.tvb(ByteArray.new(bin_to_hex(sso_dec_packet)), "SSO Decrypted Packet")())

    local sso_packer_reader = Reader.new(sso_dec_packet)
    local sso_header = sso_packer_reader:read_bytes_with_length("u32", true)
    -- subtree:add(sso_header, ByteArray.tvb(ByteArray.new(bin_to_hex(sso_header)), "SSO Header")())
    local sso_header_reader = Reader.new(sso_header)
    local seq = sso_header_reader:read_u32()
    sso_packet_tree:add(s_sso_packet_seq, seq)
    local appid = sso_header_reader:read_u32()
    sso_packet_tree:add(s_sso_packet_appid, appid)
    local locale_id = sso_header_reader:read_u32()
    sso_packet_tree:add(s_sso_packet_locale_id, locale_id)
    sso_header_reader:read_bytes(12)
    local tgt = sso_header_reader:read_bytes_with_length("u32", true)
    sso_packet_tree:add(s_sso_packet_tgt, ByteArray.tvb(ByteArray.new(bin_to_hex(tgt)), "tgt")())
    local cmd = sso_header_reader:read_string_with_length("u32", true)
    sso_packet_tree:add(s_sso_packet_cmd, cmd)
    sso_header_reader:read_bytes_with_length("u32", true)
    local guid = sso_header_reader:read_bytes_with_length("u32", true)
    sso_packet_tree:add(s_sso_packet_guid, ByteArray.tvb(ByteArray.new(bin_to_hex(guid)), "guid")())
    sso_header_reader:read_bytes_with_length("u32", true)
    local app_version = sso_header_reader:read_string_with_length("u16", true)
    sso_packet_tree:add(s_sso_packet_app_version, app_version)
    local proto_head = sso_header_reader:read_bytes_with_length("u32", true)
    sso_packet_tree:add(s_sso_packet_head, ByteArray.tvb(ByteArray.new(bin_to_hex(proto_head)), "head")()) --proto
    -- sso body
    local sso_body_data = sso_packer_reader:read_bytes_with_length("u32", true)
    sso_packet_tree:add(s_sso_packet_data, ByteArray.tvb(ByteArray.new(bin_to_hex(sso_body_data)), "SSO Packet Body")()) --proto
end

ntqq_protocol.fields = {
    -- send
    s_packet_length, s_sso_head_d2, s_sso_head_uin, 
    s_sso_decrept_packet,
    s_sso_packet_seq, s_sso_packet_appid, s_sso_packet_locale_id, s_sso_packet_tgt, s_sso_packet_cmd, s_sso_packet_guid, s_sso_packet_app_version, s_sso_packet_head,
    s_sso_packet_data,
    -- recv
    r_packet_length, r_sso_resp_type, r_sso_header_enc_flag, r_sso_header_uin, 
    r_sso_decrypt_packet, 
    r_sso_packet_compress_type, r_sso_packet_seq, r_sso_packet_ret_code, r_sso_packet_session_id, r_sso_packet_extra, r_sso_packet_cmd,
    r_sso_packet_data
}

function ntqq_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = ntqq_protocol.name
    if pinfo.src_port == ntqq_protocol.prefs.port then
        ntqq_protocol_recv_dissector(buffer, pinfo, tree)
    end
    if pinfo.dst_port == ntqq_protocol.prefs.port then
        ntqq_protocol_send_dissector(buffer, pinfo, tree)
    end
end

local tcp_port = DissectorTable.get("tcp.port")
if tcp_port then
    tcp_port:add(ntqq_protocol.prefs.port, ntqq_protocol)
end
