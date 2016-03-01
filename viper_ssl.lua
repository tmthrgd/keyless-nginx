local ffi = require "ffi"
local base = require "resty.core.base"

local C = ffi.C
local ffi_str = ffi.string
local getfenv = getfenv
local error = error
local errmsg = base.get_errmsg_ptr()
local get_size_ptr = base.get_size_ptr
local FFI_DECLINED = base.FFI_DECLINED
local FFI_OK = base.FFI_OK


ffi.cdef[[
int ngx_http_viper_lua_ffi_ssl_client_has_ecdsa(ngx_http_request_t *r, char **err);

int ngx_http_viper_lua_ffi_ssl_server_addr(ngx_http_request_t *r, char **addr, size_t *addrlen, int *addrtype, char **err);
]]


local _M = {}

local charpp = ffi.new("char*[1]")
local intp = ffi.new("int[1]")

function _M.has_ecdsa()
	local r = getfenv(0).__ngx_req
	if not r then
		return error("no request found")
	end

	local rc = C.ngx_http_viper_lua_ffi_ssl_client_has_ecdsa(r, errmsg)
	if rc == FFI_OK then
		return true
	elseif rc == FFI_DECLINED then
		return false
	end

	return nil, ffi_str(errmsg[0])
end

local addr_types = {
	[0] = "unix",
	[1] = "inet",
	[2] = "inet6",
}

function _M.server_addr()
	local r = getfenv(0).__ngx_req
	if not r then
		return error("no request found")
	end

	local sizep = get_size_ptr()

	local rc = C.ngx_http_viper_lua_ffi_ssl_server_addr(r, charpp, sizep, intp, errmsg)
	if rc == FFI_OK then
		local typ = addr_types[intp[0]]
		if not typ then
			return nil, nil, "unknown address type: " .. intp[0]
		end

		return ffi_str(charpp[0], sizep[0]), typ
	end

	return nil, nil, ffi_str(errmsg[0])
end

return _M
