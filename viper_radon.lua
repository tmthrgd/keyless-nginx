local ffi = require "ffi"
local base = require "resty.core.base"

local C = ffi.C
local ffi_str = ffi.string
local getfenv = getfenv
local error = error
local errmsg = base.get_errmsg_ptr()
local FFI_OK = base.FFI_OK


ffi.cdef[[
int ngx_http_viper_lua_ffi_radon_set_private_key(ngx_http_request_t *r, const char *sock, size_t sock_len, char **err);
]]


local _M = {}

function _M.set_private_key(sock)
	local r = getfenv(0).__ngx_req
	if not r then
		return error("no request found")
	end

	local rc = C.ngx_http_viper_lua_ffi_radon_set_private_key(r, sock, #sock, errmsg)
	if rc == FFI_OK then
		return true
	end

	return nil, ffi_str(errmsg[0])
end

return _M
