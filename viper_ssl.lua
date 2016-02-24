local ffi = require "ffi"
local base = require "resty.core.base"

local C = ffi.C
local ffi_str = ffi.string
local getfenv = getfenv
local error = error
local errmsg = base.get_errmsg_ptr()
local FFI_DECLINED = base.FFI_DECLINED
local FFI_OK = base.FFI_OK


ffi.cdef[[
int ngx_http_viper_lua_ffi_ssl_client_has_ecdsa(ngx_http_request_t *r, char **err);
]]


local _M = {}

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

return _M
