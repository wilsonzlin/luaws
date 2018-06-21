local Utils = require('Base.Utils')

local Signature = {}
Signature.__index = Signature

local function generateCanonicalRequest(httpRequest)
    local method = httpRequest.method
    local host = httpRequest.host
    local path = httpRequest.path
    local queryArgs = httpRequest.args -- Can be nil
    local headers = httpRequest.headers -- Can be nil
    local body = httpRequest.body -- Can be nil
    local payloadHash = httpRequest.payloadHash -- Can be nil

    if not method or not host or not path then
        error({ message = "Missing arguments", code = 97 })
    end

    local canonicalRequest = {
        method,
        Utils.percentEncodeBytes(path, false),
    }

    if not queryArgs then
        table.insert(canonicalRequest, "")
    else
        local queryParams = {}
        local encodedParamsMap = {}

        for k, v in pairs(queryArgs) do
            local kencoded = Utils.percentEncodeBytes(k)
            encodedParamsMap[kencoded] = v
            table.insert(queryParams, kencoded)
        end
        table.sort(queryParams)

        local queryAWSEncoded = {}

        for _, k in ipairs(queryParams) do
            local v = encodedParamsMap[k]
            local vType = type(v)
            if v == true then
                table.insert(queryAWSEncoded, k .. '=')
            elseif v == false then
                -- skip
            elseif vType ~= "string" and vType ~= "number" then
                error({ message = "Unrecognised query arg value type: " .. vType, code = 267 })
            else
                table.insert(queryAWSEncoded, k .. '=' .. Utils.percentEncodeBytes(v))
            end
        end

        table.insert(canonicalRequest, table.concat(queryAWSEncoded, '&'))
    end

    local headerNames = { "host" }
    local headersLCMap = { host = host }
    if headers then
        for name, value in pairs(headers) do
            local lc = name:lower()
            table.insert(headerNames, lc)
            headersLCMap[lc] = value
        end
        table.sort(headerNames)
    end
    local signedHeaders = table.concat(headerNames, ';')

    for _, name in ipairs(headerNames) do
        table.insert(canonicalRequest, name .. ':' .. headersLCMap[name])
    end

    table.insert(canonicalRequest, "")
    table.insert(canonicalRequest, signedHeaders)

    local contentSha256
    if payloadHash then
        contentSha256 = payloadHash
    elseif headers then
        for headerName, headerValue in pairs(headers) do
            if headerName:lower() == "x-amz-content-sha256" then
                contentSha256 = headerValue
                break
            end
        end
    end
    if not contentSha256 then
        contentSha256 = Utils.hexEncode(Utils.hash(Utils.HASH_ALGO_SHA256, body or ""))
    end

    table.insert(canonicalRequest, contentSha256)

    return Utils.hexEncode(Utils.hash(Utils.HASH_ALGO_SHA256, table.concat(canonicalRequest, '\n'))), signedHeaders
end

local function deriveSigningKey(values)
    local secretAccessKey = values.secretAccessKey
    local region = values.region
    local service = values.service
    local isoDate = values.isoDate

    if not secretAccessKey or not region or not service or not isoDate then
        error({ message = "Missing arguments", code = 95 })
    end

    local dateKey = Utils.hmac(Utils.HMAC_ALGO_SHA256, { secret = "AWS4" .. secretAccessKey, data = isoDate })
    local dateRegionKey = Utils.hmac(Utils.HMAC_ALGO_SHA256, { secret = dateKey, data = region })
    local dateRegionServiceKey = Utils.hmac(Utils.HMAC_ALGO_SHA256, { secret = dateRegionKey, data = service })
    local signingKey = Utils.hmac(Utils.HMAC_ALGO_SHA256, { secret = dateRegionServiceKey, data = "aws4_request" })

    return signingKey
end

local function sign(derivedKey, stringToSign)
    return (Utils.hexEncode(Utils.hmac(Utils.HMAC_ALGO_SHA256, { data = stringToSign, secret = derivedKey })))
end

function Signature:new(httpRequest)
    local isoDateTime = httpRequest.isoDateTime -- Required, will not be auto generated
    local expires = httpRequest.expires -- Can be nil
    local method = httpRequest.method -- Must be GET for signed URLs
    local host = httpRequest.host
    local path = httpRequest.path
    local queryArgs = httpRequest.args -- Can be nil
    local headers = httpRequest.headers -- Can be nil
    local body = httpRequest.body -- Can be nil
    local payloadHash = httpRequest.payloadHash -- Can be nil
    local service = httpRequest.service
    local region = httpRequest.region
    local accessKeyId = httpRequest.accessKeyId
    local secretAccessKey = httpRequest.secretAccessKey

    if not isoDateTime or not method or not host or not path or not service or not region or not accessKeyId or not secretAccessKey then
        error({ message = "Missing arguments", code = 96 })
    end

    local isoDate = isoDateTime:sub(1, 8)

    return setmetatable({
        isoDateTime = isoDateTime,
        isoDate = isoDate,
        expires = expires,
        method = method,
        host = host,
        path = path,
        args = queryArgs,
        headers = headers,
        body = body,
        payloadHash = payloadHash,
        service = service,
        region = region,
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    }, Signature)
end

function Signature:toAuthHeader()
    local canonicalRequest, signedHeadersJoined = generateCanonicalRequest({
        method = self.method,
        host = self.host,
        path = self.path,
        args = self.args,
        headers = self.headers,
        body = self.body,
    })

    local stringToSign = table.concat({
        "AWS4-HMAC-SHA256",
        self.isoDateTime,
        table.concat({ self.isoDate, self.region, self.service, "aws4_request" }, '/'),
        canonicalRequest,
    }, '\n')

    local derivedKey = deriveSigningKey({
        secretAccessKey = self.secretAccessKey,
        region = self.region,
        service = self.service,
        isoDate = self.isoDate,
    })

    local signature = sign(derivedKey, stringToSign)

    local headerValue = string.format("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s", self.accessKeyId, self.isoDate, self.region, self.service, signedHeadersJoined, signature)

    return headerValue
end

--[[
    There are several characteristics of requests made by a URL to keep in mind:

    - They cannot have body data
    - They always use the GET method
    - They cannot add, edit or remove any headers to/on/from the ones the client wishes to send
--]]
function Signature:toQueryArgs()
    if self.method ~= "GET" then
        error({ message = "Cannot generate query string signature for non-GET request", code = 266 })
    end

    if self.headers or self.body then
        error({ message = "Headers and bodies are not allowed for query string signatures", code = 265 })
    end

    local queryArgs = {}
    if self.args then
        for k, v in pairs(self.args) do
            queryArgs[k] = v
        end
    end

    local authQueryArgs = {}
    authQueryArgs["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256"
    authQueryArgs["X-Amz-Credential"] = table.concat({ self.accessKeyId, self.isoDate, self.region, self.service, "aws4_request" }, '/')
    authQueryArgs["X-Amz-Date"] = self.isoDateTime
    authQueryArgs["X-Amz-Expires"] = self.expires
    authQueryArgs["X-Amz-SignedHeaders"] = "host"

    for k, v in pairs(authQueryArgs) do
        queryArgs[k] = v
    end

    local canonicalRequest = generateCanonicalRequest({
        method = self.method,
        host = self.host,
        path = self.path,
        args = queryArgs,
        payloadHash = self.payloadHash,
    })

    local stringToSign = table.concat({
        "AWS4-HMAC-SHA256",
        self.isoDateTime,
        table.concat({ self.isoDate, self.region, self.service, "aws4_request" }, '/'),
        canonicalRequest
    }, '\n')

    local derivedKey = deriveSigningKey({
        secretAccessKey = self.secretAccessKey,
        region = self.region,
        service = self.service,
        isoDate = self.isoDate,
    })

    local signature = sign(derivedKey, stringToSign)
    authQueryArgs["X-Amz-Signature"] = signature

    return authQueryArgs
end

return Signature
