local DateTime = require('Base.DateTime')
local JSON = require('cjson')
local Signature = require('AWS.Signature')
local Utils = require('Base.Utils')

local EC2 = {}

local function constructEndpointHost(region)
    return region == "us-east-1" and "ec2.amazonaws.com" or string.format("ec2.%s.amazonaws.com", region)
end

local function constructUrl(host, path, query)
    return "https://" .. host .. path .. (query and ("?" .. query) or "")
end

function EC2.newHttpRequest(details)
    local method = details.method
    local action = details.action
    local parameters = details.parameters -- Can be nil
    local body = details.body -- Can be nil; must be JSON-serialisable table if provided
    local region = details.region
    local accessKeyId = details.accessKeyId
    local secretAccessKey = details.secretAccessKey

    if not method or not action or not region or not accessKeyId or not secretAccessKey then
        error({ message = "Missing arguments", code = 94 })
    end

    local isoDateTime = details.isoDateTime or DateTime.utcISODateTime()

    local host = constructEndpointHost(region)
    local path = "/"

    local httpRequest = {}
    httpRequest.method = method
    httpRequest.headers = {}
    httpRequest.headers["x-amz-date"] = isoDateTime

    local queryArgs = {}
    if parameters then
        for k, v in pairs(parameters) do
            queryArgs[k] = v
        end
    end
    queryArgs["Action"] = action
    queryArgs["Version"] = "2016-11-15"

    if body then
        httpRequest.headers["Content-Type"] = "application/json"
        httpRequest.body = JSON.encode(body)
    end

    httpRequest.headers["Authorization"] = Signature:new({
        isoDateTime = isoDateTime,
        method = method,
        host = host,
        path = path,
        args = queryArgs,
        headers = httpRequest.headers,
        service = "ec2",
        region = region,
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    }):toAuthHeader()

    local query = Utils.serialiseURLEncoded(queryArgs)
    httpRequest.url = constructUrl(host, path, query)

    return httpRequest
end

return EC2
