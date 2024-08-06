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
local sso_recv_length = ProtoField.uint32("sso_recv_length", "sso_recv_length", base.DEC)
local sso_resp_type = ProtoField.uint32("sso_resp_type", "sso_resp_type", base.DEC)
local sso_header_enc_flag = ProtoField.uint32("sso_header_enc_flag", "sso_header_enc_flag", base.DEC)
local sso_header_uin = ProtoField.string("sso_header_uin", "sso_header_uin", base.NONE)
local sso_body_compress_type = ProtoField.uint32("sso_body_compress_type", "sso_body_compress_type", base.DEC)
local sso_body_recv = ProtoField.bytes("sso_body", "sso_body", base.NONE)
local sso_body_seq = ProtoField.string("sso_body.seq", "sso_body.seq", base.NONE)
local sso_body_ret_code = ProtoField.string("sso_body.ret_code", "sso_body.ret_code", base.NONE)
local sso_body_session_id = ProtoField.bytes("sso_body.session_id", "sso_body.session_id", base.NONE)
local sso_body_extra = ProtoField.string("sso_body.extra", "sso_body.extra", base.NONE)
local sso_body_cmd = ProtoField.string("sso_body.cmd", "sso_body.cmd", base.NONE)
local sso_body_data = ProtoField.bytes("sso_body.data", "sso_body.data", base.NONE)

local function parse_sso_frame(buffer, is_oicq_body)
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
    local body_len = reader:read_u32()
    subtree:add(sso_recv_length, body_len)
    if (lost_segment() == nil) then
        pdu_impl(body_len, buffer, pinfo)
    end
    -- body
    local body = reader:read_bytes(body_len - 4)
    reader = Reader.new(body)
    local resp_type = reader:read_i32()
    subtree:add(sso_resp_type, resp_type)
    if resp_type ~= responseType.RequestTypeLogin and resp_type ~= responseType.RequestTypeSimple and resp_type ~= responseType.RequestTypeNT then
        error("invalid packet type")
    end

    local enc_flag = reader:read_u8()
    subtree:add(sso_header_enc_flag, enc_flag)
    reader:read_u8()
    local uin_str = reader:read_string_with_length("u32", true)
    local uin = tonumber(uin_str)
    subtree:add(sso_header_uin, uin)
    local body = reader:read_bytes(reader:remaining())
    -- sso body decrypt
    local sso_dec_body_tvb
    if enc_flag == 0 then
        sso_dec_body_tvb = ByteArray.tvb(body, "SSO Decrypted Data - 0")
    elseif enc_flag == 1 then
        local sso_dec_body = tea.decrypt_qq(hex_to_bin(ntqq_protocol.prefs.d2_key), body)
        local sso_dec_body_data = ByteArray.new(bin_to_hex(sso_dec_body))
        sso_dec_body_tvb = ByteArray.tvb(sso_dec_body_data, "SSO Decrypted Data - 1")
    elseif enc_flag == 2 then
        local sso_dec_body = tea.decrypt_qq(string.rep("\0", 16), body)
        local sso_dec_body_data = ByteArray.new(bin_to_hex(sso_dec_body))
        sso_dec_body_tvb = ByteArray.tvb(sso_dec_body_data, "SSO Decrypted Data - 2")
    end
    subtree:add(sso_body_recv, sso_dec_body_tvb())
    -- sso body paste
    local sso_frame = parse_sso_frame(sso_dec_body_tvb():raw(), enc_flag == 2)
    subtree:add(sso_body_compress_type, sso_frame.compress_type)
    subtree:add(sso_body_seq, sso_frame.seq)
    subtree:add(sso_body_ret_code, sso_frame.ret_code)
    subtree:add(sso_body_session_id, ByteArray.tvb(ByteArray.new(bin_to_hex(sso_frame.session_id)), "session_id")())
    subtree:add(sso_body_extra, sso_frame.extra)
    subtree:add(sso_body_cmd, sso_frame.cmd)
    subtree:add(sso_body_data, ByteArray.tvb(ByteArray.new(bin_to_hex(sso_frame.data)), "data")())
end

-- send protocol
local sso_send_length = ProtoField.uint32("sso_send_length", "sso_send_length", base.DEC)
local sso_head_d2 = ProtoField.bytes("sso_head_d2", "sso_head_d2", base.NONE)
local sso_head_uin = ProtoField.string("sso_head_uin", "sso_head_uin", base.NONE)
local sso_packet = ProtoField.bytes("sso_packet", "sso_packet", base.NONE) -- tea start from here
local sso_header = ProtoField.bytes("sso_packet.sso_header", "sso_packet.sso_header", base.NONE)
local sso_header_seq = ProtoField.uint32("sso_packet.sso_header.seq", "sso_packet.sso_header.seq", base.DEC)
local sso_header_appid = ProtoField.uint32("sso_packet.sso_header.appid", "sso_packet.sso_header.appid", base.DEC)
local sso_header_locale_id = ProtoField.uint32("sso_packet.sso_header.locale_id", "sso_packet.sso_header.locale_id",
    base.DEC)
local sso_header_tgt = ProtoField.bytes("sso_packet.sso_header.tgt", "sso_packet.sso_header.tgt", base.NONE)
local sso_header_cmd = ProtoField.string("sso_packet.sso_header.cmd", "sso_packet.sso_header.cmd", base.NONE)
local sso_header_guid = ProtoField.bytes("sso_packet.sso_header.guid", "sso_packet.sso_header.guid", base.NONE)
local sso_header_app_version = ProtoField.string("sso_packet.sso_header.app_version", "sso_packet.sso_header.app_version",
    base.NONE)
local sso_header_head = ProtoField.bytes("sso_packet.sso_header.head", "sso_packet.sso_header.head", base.NONE)
local sso_body_send = ProtoField.bytes("sso_packet.sso_body", "sso_packet.sso_body", base.NONE)

local function ntqq_protocol_send_dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = ntqq_protocol.name
    local subtree = tree:add(ntqq_protocol, buffer())
    local reader = Reader.new(buffer:raw())
    local body_len = reader:read_u32()
    subtree:add(sso_send_length, body_len)
    if (lost_segment() == nil) then
        pdu_impl(body_len, buffer, pinfo)
    end
    -- body
    local body = reader:read_bytes(body_len - 4)
    reader = Reader.new(body)
    reader:read_u32()
    reader:read_u8()
    local d2 = reader:read_bytes_with_length("u32", true)
    subtree:add(sso_head_d2, ByteArray.tvb(ByteArray.new(bin_to_hex(d2)), "d2key")())
    reader:read_u8()
    local uin = reader:read_string_with_length("u32", true)
    subtree:add(sso_head_uin, uin)
    local enc_sso_packet = reader:read_bytes(reader:remaining())
    local dec_sso_packet = tea.decrypt_qq(hex_to_bin(ntqq_protocol.prefs.d2_key), enc_sso_packet)
    subtree:add(sso_packet, ByteArray.tvb(ByteArray.new(bin_to_hex(dec_sso_packet)), "SSO Packet")())
    -- sso
    -- sso header
    local sso_reader = Reader.new(dec_sso_packet)
    -- sso header read
    local sso_header = sso_reader:read_bytes_with_length("u32", true)
    subtree:add(sso_header, ByteArray.tvb(ByteArray.new(bin_to_hex(sso_header)), "SSO Header")())
    local sso_header_reader = Reader.new(sso_header)
    local seq = sso_header_reader:read_u32()
    subtree:add(sso_header_seq, seq)
    local appid = sso_header_reader:read_u32()
    subtree:add(sso_header_appid, appid)
    local locale_id = sso_header_reader:read_u32()
    subtree:add(sso_header_locale_id, locale_id)
    sso_header_reader:read_bytes(12)
    local tgt = sso_header_reader:read_bytes_with_length("u32", true)
    subtree:add(sso_header_tgt, ByteArray.tvb(ByteArray.new(bin_to_hex(tgt)), "tgt")())
    local cmd = sso_header_reader:read_string_with_length("u32", true)
    subtree:add(sso_header_cmd, cmd)
    sso_header_reader:read_bytes_with_length("u32", true)
    local guid = sso_header_reader:read_bytes_with_length("u32", true)
    subtree:add(sso_header_guid, ByteArray.tvb(ByteArray.new(bin_to_hex(guid)), "guid")())
    sso_header_reader:read_bytes_with_length("u32", true)
    local app_version = sso_header_reader:read_string_with_length("u16", true)
    subtree:add(sso_header_app_version, app_version)
    local proto_head = sso_header_reader:read_bytes_with_length("u32", true)
    subtree:add(sso_header_head, ByteArray.tvb(ByteArray.new(bin_to_hex(proto_head)), "proto head")())
    -- sso body
    local sso_body = sso_reader:read_bytes_with_length("u32", true)
    subtree:add(sso_body_send, ByteArray.tvb(ByteArray.new(bin_to_hex(sso_body)), "SSO Packet Body")())
end

ntqq_protocol.fields = {
    -- send
    sso_send_length, sso_head_d2, sso_head_uin, sso_packet, sso_header,
    sso_header_seq, sso_header_appid, sso_header_locale_id, sso_header_tgt,
    sso_header_cmd, sso_header_guid, sso_header_app_version, sso_header_head, sso_body_send,
    --recv
    sso_recv_length, sso_resp_type, sso_header_enc_flag, sso_header_uin, 
    sso_body_compress_type, sso_body_recv, sso_body_seq, sso_body_ret_code, sso_body_session_id, sso_body_extra, sso_body_cmd, sso_body_data
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
