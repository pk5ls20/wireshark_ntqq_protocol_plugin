-- ref https://github.com/LagrangeDev/lagrange-python
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

function Reader:read_struct(format)
    local values = {}
    for i = 1, #format do
        local f = format:sub(i, i)
        if f == 'I' then 
            table.insert(values, self:read_u32())
        elseif f == 'i' then 
            local val = self:read_u32()
            if val >= 0x80000000 then
                val = val - 0x100000000
            end
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
            length = self:read_u54() - 8
        end
    else
        if prefix == "u8" then
            length = self:read_u8()
        elseif prefix == "u16" then
            length = self:read_u16()
        elseif prefix == "u32" then
            length = self:read_u32()
        elseif prefix == "u64" then
            length = self:read_u54()
        end
    end
    return self:read_bytes(length)
end

function Reader:read_string_with_length(prefix, with_prefix)
    local bytes = self:read_bytes_with_length(prefix, with_prefix)
    return bytes 
end


local function hex_to_bin(hexstr)
    return (hexstr:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

local function bin_to_hex(str)
    return (str:gsub('.', function(c)
        return string.format('%02x', string.byte(c))
    end))
end

-- protocol
local ntqq_protocol = Proto("ntqq_protocol", "NTQQ Protocol")
ntqq_protocol.prefs.d2_key = Pref.string("D2Key", "", "")

-- base
local sso_header_enc_flag = ProtoField.uint32("sso_header_enc_flag", "sso_header_enc_flag", base.DEC)
local sso_header_uin = ProtoField.string("sso_header_uin", "sso_header_uin", base.NONE)
local sso_body = ProtoField.bytes("sso_body", "sso_body", base.NONE)
local sso_body_seq = ProtoField.string("sso_body.seq", "sso_body.seq", base.NONE)
local sso_body_ret_code = ProtoField.string("sso_body.ret_code", "sso_body.ret_code", base.NONE)
local sso_body_session_id = ProtoField.bytes("sso_body.session_id", "sso_body.session_id", base.NONE)
local sso_body_extra = ProtoField.string("sso_body.extra", "sso_body.extra", base.NONE)
local sso_body_cmd = ProtoField.string("sso_body.cmd", "sso_body.cmd", base.NONE)
local sso_body_data = ProtoField.bytes("sso_body.data", "sso_body.data", base.NONE)

ntqq_protocol.fields = {
    sso_header_enc_flag, sso_header_uin, sso_body,
    sso_body_seq, sso_body_ret_code, sso_body_session_id,
    sso_body_extra, sso_body_cmd, sso_body_data
}

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
        -- TODO: zlib decompress
        -- data = zlib.inflate(data)
        error("zlib decompress not implemented")
    elseif compress_type == 2 then
        data = string.sub(data, 5)
    end

    if is_oicq_body and string.find(cmd, "wtlogin.login") then
        -- TODO: decrypt oicq body
        error("decrypt oicq body not implemented")
    end

    return {
        seq = seq,
        ret_code = ret_code,
        session_id = session_id, 
        extra = extra,
        cmd = cmd,
        data = data,
    }
end

function ntqq_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = ntqq_protocol.name
    -- package.cpath = "C:\\Users\\pk5ls\\Desktop\\ntqq-explore\\wireshark_ntqq_protocolcol\\?.dll;" .. package.cpath
    -- print(package.cpath)
    
    local tea = require("tea")

    local offset = 4 
    local enc_flag_len = 1
    local uin_len_field_len = 1

    local new_buffer = buffer(offset):range()
    -- print("new_buffer: ", new_buffer:bytes():tohex()) 
    local subtree = tree:add(ntqq_protocol, new_buffer)

    local sso_header_enc_flag_buf = new_buffer(offset, enc_flag_len)
    local sso_header_enc_flag_buf_val = new_buffer(offset, enc_flag_len):uint()
    subtree:add(sso_header_enc_flag, sso_header_enc_flag_buf)
    -- print("sso_header_enc_flag: ", type(sso_header_enc_flag_buf_val), sso_header_enc_flag_buf_val)

    local sso_header_uin_len = new_buffer(4 + 4 + 1, uin_len_field_len):uint() - 4
    local sso_header_uin_value = new_buffer(4 + 4 + 1 + 1, sso_header_uin_len):raw()
    subtree:add(sso_header_uin, sso_header_uin_value)
    -- print("sso_header_uin, len= ", sso_header_uin_len)
    -- print("sso_header_uin: ", new_buffer(4 + 4 + 1 + 1, sso_header_uin_len):raw())

    local body_offset = (4 + 4 + 1 + 1) + sso_header_uin_len

    local tea_key = ntqq_protocol.prefs.d2_key
    local sso_raw_body = new_buffer(body_offset):raw() 
    -- print("sso_raw_body", bin_to_hex(sso_raw_body))

    local sso_dec_body_tvb
    if sso_header_enc_flag_buf_val == 0 then
        sso_dec_body_tvb = ByteArray.tvb(sso_raw_body, "SSO Decrypted Data - 0")
    elseif sso_header_enc_flag_buf_val == 1 then
        local sso_dec_body = tea.decrypt_qq(hex_to_bin(tea_key), sso_raw_body)
        local sso_dec_body_data = ByteArray.new(bin_to_hex(sso_dec_body))
        -- print("sso_decrypted_body", bin_to_hex(sso_dec_body))
        sso_dec_body_tvb = ByteArray.tvb(sso_dec_body_data, "SSO Decrypted Data - 1")
    elseif sso_header_enc_flag_buf_val == 2 then
        local sso_dec_body = tea.decrypt_qq(string.rep("\0", 16), sso_raw_body)
        local sso_dec_body_data = ByteArray.new(bin_to_hex(sso_dec_body))
        -- print("sso_decrypted_body", bin_to_hex(sso_dec_body))
        sso_dec_body_tvb = ByteArray.tvb(sso_dec_body_data, "SSO Decrypted Data - 2")
    end
    subtree:add(sso_body, sso_dec_body_tvb())

    local res = parse_sso_frame(sso_dec_body_tvb():raw(), sso_header_enc_flag_buf_val==2)
    local res_session_id = ByteArray.new(bin_to_hex(res.session_id))
    local res_data = ByteArray.new(bin_to_hex(res.data))
    subtree:add(sso_body_seq, res.seq)
    subtree:add(sso_body_ret_code, res.ret_code)
    subtree:add(sso_body_session_id, ByteArray.tvb(res_session_id, "SSO Session ID")())
    subtree:add(sso_body_extra, res.extra)
    subtree:add(sso_body_cmd, res.cmd)
    subtree:add(sso_body_data, ByteArray.tvb(res_data, "SSO Data")())
end

local tcp_port = DissectorTable.get("tcp.port")
if tcp_port then
    tcp_port:add(8080, ntqq_protocol)
end
