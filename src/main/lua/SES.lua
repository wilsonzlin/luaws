local DateTime = require('Base.DateTime')
local HTTP = require('Base.HTTP.Request')
local Signature = require('AWS.Signature')
local Utils = require('Base.Utils')

local SES = {}

function SES.newHttpRequest(details)
    local method = details.method -- Invalid
    local action = details.action
    local parameters = details.parameters -- Must be provided. Provide empty table if necessary
    local region = details.region
    local accessKeyId = details.accessKeyId
    local secretAccessKey = details.secretAccessKey

    if not action or not parameters or not region or not accessKeyId or not secretAccessKey then
        error({ message = "Missing arguments", code = 418 })
    end

    if method then
        error({ message = "Unsuppported arguments provided", code = 384 })
    end

    method = "POST"

    local isoDateTime = details.isoDateTime or DateTime.utcISODateTime()

    local host = string.format("email.%s.amazonaws.com", region)
    local path = "/"

    local httpRequest = {}
    httpRequest.method = method
    httpRequest.headers = {}
    httpRequest.headers["x-amz-date"] = isoDateTime
    httpRequest.headers["Content-Type"] = "application/x-www-form-urlencoded"
    httpRequest.body = Utils.serialiseURLEncoded(Utils.concat(parameters, {
        Action = action,
    }))
    -- Content-Length should be added by HTTP request sender

    httpRequest.headers["Authorization"] = Signature:new({
        isoDateTime = isoDateTime,
        method = method,
        host = host,
        path = path,
        headers = httpRequest.headers,
        body = httpRequest.body,
        service = "ses",
        region = region,
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    }):toAuthHeader()

    httpRequest.url = string.format("https://%s%s", host, path)

    return httpRequest
end

function SES.sendEmail(details)
    local from = details.from
    local to = details.to -- Can be a single string or a table of strings
    local cc = details.cc -- Can be nil, a single string or a table of strings
    local bcc = details.bcc -- Can be nil, a single string or a table of strings
    local subject = details.subject
    local body = details.body
    local replyTo = details.replyTo -- Can be nil, a single string or a table of strings
    local region = details.region
    local accessKeyId = details.accessKeyId
    local secretAccessKey = details.secretAccessKey

    if not from or not to or not subject or not body or not region or not accessKeyId or not secretAccessKey then
        error({ message = "Missing arguments", code = 390 })
    end

    local parameters = {}

    parameters["Source"] = from

    if type(to) == "table" then
        for i, v in ipairs(to) do
            parameters["Destination.ToAddresses.member." .. i] = v
        end
    else
        parameters["Destination.ToAddresses.member.1"] = to
    end

    if type(cc) == "table" then
        for i, v in ipairs(cc) do
            parameters["Destination.CcAddresses.member." .. i] = v
        end
    else
        parameters["Destination.CcAddresses.member.1"] = cc
    end

    if type(bcc) == "table" then
        for i, v in ipairs(bcc) do
            parameters["Destination.BccAddresses.member." .. i] = v
        end
    else
        parameters["Destination.BccAddresses.member.1"] = bcc
    end

    parameters["Message.Subject.Data"] = subject
    parameters["Message.Body.Html.Data"] = body

    if type(replyTo) == "table" then
        for i, v in ipairs(replyTo) do
            parameters["ReplyToAddresses.member." .. i] = v
        end
    else
        parameters["ReplyToAddresses.member.1"] = replyTo
    end

    local request = SES.newHttpRequest({
        action = "SendEmail",
        parameters = parameters,
        region = region,
        accessKeyId = accessKeyId,
        secretAccessKey = secretAccessKey,
    })

    HTTP.request(request)
end

return SES
