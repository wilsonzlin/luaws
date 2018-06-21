local DateTime = require('Base.DateTime')
local JSON = require('cjson')
local Signature = require('AWS.Signature')
local Utils = require('Base.Utils')

local WAF = {}

function WAF.newHttpRequest(details)
    local method = details.method -- Invalid
    local operation = details.operation
    local body = details.body or {} -- Can be nil; must be JSON-serialisable table if provided
    local region = details.region -- Invalid
    local accessKeyId = details.accessKeyId
    local secretAccessKey = details.secretAccessKey

    if not operation or not accessKeyId or not secretAccessKey then
        error({ message = "Missing arguments", code = 98 })
    end

    if method or region then
        error({ message = "AWS WAF API requests do not have variant methods or regions", code = 99 })
    end
    method = "POST"

    local isoDateTime = details.isoDateTime or DateTime.utcISODateTime()

    local host = "waf.amazonaws.com"
    local path = "/"

    local httpRequest = {}
    httpRequest.method = method
    httpRequest.headers = {}
    httpRequest.headers["x-amz-date"] = isoDateTime
    httpRequest.headers["x-amz-target"] = string.format("AWSWAF_%s.%s", "20150824", operation)
    httpRequest.headers["Content-Type"] = "application/x-amz-json-1.1"
    httpRequest.body = JSON.encode(body)
    -- Content-Length should be added by HTTP request sender

    httpRequest.headers["Authorization"] = Signature:new({
        isoDateTime = isoDateTime,
        method = method,
        host = host,
        path = path,
        headers = httpRequest.headers,
        body = httpRequest.body,
        service = "waf",
        region = "us-east-1",
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    }):toAuthHeader()

    httpRequest.url = string.format("https://%s%s", host, path)

    return httpRequest
end

return WAF
