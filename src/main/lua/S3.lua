local Utils = require('Base.Utils')
local Assert = require('Base.Condition.Assert')
local HTTP = require('Base.HTTP.Request')
local DateTime = require('Base.DateTime')
local Signature = require('AWS.Signature')

local S3 = {}

S3.STORAGE_CLASS = {
    STANDARD = "STANDARD",
    STANDARD_IA = "STANDARD_IA",
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY",
}

-- TIP: Generally, using virtual host URLs are bad, as the HTTP request connection cannot be reused often with Keep-Alive (due to the domain being different frequently)
local function constructRestUrlHost(bucket, region, useVirtualHost)
    return (useVirtualHost and bucket) and string.format("%s.s3-%s.amazonaws.com", bucket, region) or (region == "us-east-1" and "s3.amazonaws.com" or string.format("s3-%s.amazonaws.com", region))
end

local function constructRestUrlPath(path, bucket, useVirtualHost)
    return ((useVirtualHost or not bucket) and "" or string.format("/%s", bucket)) .. path
end

local function constructHttpsUrl(host, path, query)
    return "https://" .. host .. path .. (query and #query > 0 and ("?" .. query) or "")
end

function S3.newSignedURL(details)
    local useVirtualHost = details.useVirtualHost -- Optional boolean (true|false|nil, default nil)
    local expires = details.expires -- How many seconds the URL is valid for since creation (NOT timestamp)
    local method = details.method -- Must be GET
    local path = details.path
    local origQueryArgs = details.args -- Can be nil
    local body = details.body -- Invalid
    local md5 = details.md5 -- Invalid
    local contentType = details.contentType -- Invalid
    local storageClass = details.storageClass -- Invalid
    local bucket = details.bucket -- Can be nil (e.g. operations on the service)
    local region = details.region
    local accessKeyId = details.accessKeyId
    local secretAccessKey = details.secretAccessKey

    if not expires or not method or not path or not region or not accessKeyId or not secretAccessKey then
        error({ message = "Missing arguments", code = 93 })
    end

    local isoDateTime = details.isoDateTime or DateTime.utcISODateTime()

    if method ~= "GET" or body or md5 or contentType or storageClass then
        error({ message = "Details were provided for a new signed URL that are not possible to use", code = 269 })
    end

    if path:sub(1, 1) ~= "/" then
        error({ message = "The path needs to start with a slash", code = 90 })
    end

    local host = constructRestUrlHost(bucket, region, useVirtualHost)
    local unescapedPath = constructRestUrlPath(path, bucket, useVirtualHost)

    local authQueryArgs = Signature:new({
        isoDateTime = isoDateTime,
        expires = expires,
        method = "GET",
        host = host,
        path = unescapedPath,
        args = origQueryArgs,
        payloadHash = "UNSIGNED-PAYLOAD",
        headers = nil,
        service = "s3",
        region = region,
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    }):toQueryArgs()

    local finalQueryArgs = {}
    for k, v in pairs(origQueryArgs) do
        finalQueryArgs[k] = v
    end
    for k, v in pairs(authQueryArgs) do
        finalQueryArgs[k] = v
    end

    local queryString = Utils.serialiseURLEncoded(finalQueryArgs)

    local url = constructHttpsUrl(host, Utils.escapeURI(unescapedPath, false), queryString)
    return url
end

function S3.newHttpRequest(details)
    local useVirtualHost = details.useVirtualHost -- Optional boolean (true|false|nil, default nil)
    local method = details.method
    local path = details.path
    local queryArgs = details.args -- Can be nil
    local body = details.body -- Can be nil
    local md5 = details.md5 -- Optional boolean (true|false|nil, default nil)
    local contentType = details.contentType -- Can be nil
    local copySource = details.copySource -- Can be nil
    local storageClass = details.storageClass -- Can be nil
    local bucket = details.bucket -- Can be nil (e.g. operations on the service)
    local region = details.region
    local accessKeyId = details.accessKeyId
    local secretAccessKey = details.secretAccessKey

    if not method or not path or not region or not accessKeyId or not secretAccessKey then
        error({ message = "Missing arguments", code = 91 })
    end

    local isoDateTime = details.isoDateTime or DateTime.utcISODateTime()
    local unescapedPath = constructRestUrlPath(path, bucket, useVirtualHost)
    local host = constructRestUrlHost(bucket, region, useVirtualHost)
    local path = Utils.escapeURI(unescapedPath, false)
    local query = queryArgs and Utils.serialiseURLEncoded(queryArgs) or ""

    if path:sub(1, 1) ~= "/" then
        error({ message = "The path needs to start with a slash", code = 89 })
    end

    if md5 and not body then
        error({ message = "MD5 required but no body provided", code = 254 })
    end

    local httpRequest = {}
    httpRequest.method = method
    httpRequest.url = constructHttpsUrl(host, path, query)
    httpRequest.headers = {}
    httpRequest.body = body

    httpRequest.headers["Content-Type"] = contentType
    httpRequest.headers["Content-MD5"] = md5 and Utils.base64Encode(Utils.hash(Utils.HASH_ALGO_MD5, body), true)
    httpRequest.headers["x-amz-date"] = isoDateTime
    httpRequest.headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
    httpRequest.headers["x-amz-storage-class"] = storageClass
    httpRequest.headers["x-amz-copy-source"] = copySource

    httpRequest.headers["Authorization"] = Signature:new({
        isoDateTime = isoDateTime,
        method = method,
        host = host,
        path = unescapedPath,
        args = queryArgs,
        headers = httpRequest.headers,
        service = "s3",
        region = region,
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    }):toAuthHeader()

    return httpRequest
end

function S3.getObjectSignedURL(details)
    local fileKey = details.fileKey
    local bucket = details.bucket
    local region = details.region
    local accessKeyId = details.accessKeyId
    local secretAccessKey = details.secretAccessKey
    local expires = details.expires
    local responseFileName = details.responseFileName
    local responseContentType = details.responseContentType
    local responseCacheTime = details.responseCacheTime or 0

    local queryArgs = {}
    if responseCacheTime < 1 then
        queryArgs["response-expires"] = 0
        queryArgs["response-cache-control"] = "no-cache, no-store, must-revalidate"
    else
        queryArgs["response-expires"] = DateTime.httpHeader(DateTime.epochSeconds() + responseCacheTime)
        queryArgs["response-cache-control"] = "max-age=" .. responseCacheTime
    end

    queryArgs["response-content-type"] = responseContentType

    if responseFileName then
        queryArgs["response-content-disposition"] = string.format('attachment; filename="%s"', Utils.escapeURI(responseFileName))
    end

    local url = S3.newSignedURL({
        expires = expires,
        method = "GET",
        path = fileKey,
        args = queryArgs,
        bucket = bucket,
        region = region,
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    })

    return url
end

function S3.putObject(details)
    local fileKey = details.fileKey
    local data = details.data
    local contentType = details.contentType -- Can be nil
    local storageClass = details.storageClass -- Can be nil
    local bucket = details.bucket
    local region = details.region
    local accessKeyId = details.accessKeyId
    local secretAccessKey = details.secretAccessKey

    if not fileKey or not data or not bucket or not region or not accessKeyId or not secretAccessKey then
        error({ message = "Missing arguments", code = 92 })
    end

    local request = S3.newHttpRequest({
        method = "PUT",
        path = fileKey,
        body = data,
        md5 = true,
        contentType = contentType,
        storageClass = storageClass,
        bucket = bucket,
        region = region,
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    })

    HTTP.put(request.url, { headers = request.headers, body = request.body })
end

function S3.copyObject(details)
    local fromBucket = details.fromBucket
    local fromFileKey = details.fromFileKey
    local toBucket = details.toBucket
    local toFileKey = details.toFileKey
    local region = details.region
    local accessKeyId = details.accessKeyId
    local secretAccessKey = details.secretAccessKey

    if not fromBucket or not fromFileKey or not toBucket or not toFileKey or not region or not accessKeyId or not secretAccessKey then
        error({ message = "Missing arguments", code = 158 })
    end

    if fromFileKey:sub(1, 1) ~= "/" then
        error({ message = "The source path needs to start with a slash", code = 157 })
    end

    local request = S3.newHttpRequest({
        method = "PUT",
        path = toFileKey,
        bucket = toBucket,
        copySource = Utils.escapeURI(string.format("/%s%s", fromBucket, fromFileKey)),
        region = region,
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    })

    local response = HTTP.put(request.url, { headers = request.headers, body = request.body })
    if not response.body:find("<CopyObjectResult>") then
        error({ message = "Copy operation failed with response: " .. response.body, code = 169 })
    end
end

function S3.newMultipartUpload(details)
    local fileKey = details.fileKey
    local contentType = details.contentType -- Can be nil
    local storageClass = details.storageClass -- Can be nil
    local bucket = details.bucket
    local region = details.region
    local accessKeyId = details.accessKeyId
    local secretAccessKey = details.secretAccessKey

    if not fileKey or not bucket or not region or not accessKeyId or not secretAccessKey then
        error({ message = "Missing arguments", code = 109 })
    end

    local request = S3.newHttpRequest({
        method = "POST",
        path = fileKey,
        args = { uploads = true },
        contentType = contentType,
        storageClass = storageClass,
        bucket = bucket,
        region = region,
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    })

    local response = HTTP.post(request.url, { headers = request.headers })
    local xmlResponse = response.body

    local uploadId = xmlResponse:match("<UploadId>(.-)</UploadId>")
    if not uploadId then
        error({ message = "Invalid upload ID in response: " .. xmlResponse, code = 108 })
    end

    local nextPartNo = 1
    local ended = false
    local etags = {}

    return {
        uploadNextPart = function(data)
            if ended then
                error({ message = "Upload already ended", code = 111 })
            end

            local request = S3.newHttpRequest({
                method = "PUT",
                path = fileKey,
                args = { partNumber = nextPartNo, uploadId = uploadId },
                body = data,
                md5 = true,
                bucket = bucket,
                region = region,
                accessKeyId = accessKeyId,
                secretAccessKey = secretAccessKey,
            })

            local response = HTTP.put(request.url, { headers = request.headers, body = request.body })
            local etag = response.headers["ETag"]
            if not etag then
                error({ message = "Missing ETag header", code = 110 })
            end
            etags[nextPartNo] = etag

            nextPartNo = nextPartNo + 1
        end,
        complete = function()
            ended = true

            local requestXML = "<CompleteMultipartUpload>"
            for partNo, etag in pairs(etags) do -- Use pairs just to be safe (in case parts were added out-of-order)
                requestXML = requestXML .. string.format('<Part><PartNumber>%d</PartNumber><ETag>"%s"</ETag></Part>', partNo, Utils.escapeHTML(etag))
            end
            requestXML = requestXML .. "</CompleteMultipartUpload>"

            local request = S3.newHttpRequest({
                method = "POST",
                path = fileKey,
                args = { uploadId = uploadId },
                body = requestXML,
                bucket = bucket,
                region = region,
                accessKeyId = accessKeyId,
                secretAccessKey = secretAccessKey,
            })

            local response = HTTP.post(request.url, { headers = request.headers, body = request.body })

            -- WARNING: 200 status could be sent but the request could still have failed:
            -- https://docs.aws.amazon.com/AmazonS3/latest/API/mpUploadComplete.html
            if not response.body:find("<CompleteMultipartUploadResult ") then
                error({ message = "Failed to complete multipart upload", code = 113 })
            end
        end
    }
end

return S3
