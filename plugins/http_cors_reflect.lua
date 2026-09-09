-- http_cors_reflect.lua: arbitrary-origin reflection. A POST request with
-- an attacker Origin that is echoed back together with a permissive
-- Access-Control-Allow-* policy lets any website read authenticated
-- responses of the victim.
--
-- ctx: {host, port, service, http_status, ...}

function on_http_response(ctx)
    if ctx.service ~= "http" and ctx.service ~= "https" then return end
    if not ctx.http_status or ctx.http_status >= 500 then return end

    local conn = sleipnir.tcp_connect(ctx.host, ctx.port)
    if not conn then return end

    local req = "GET / HTTP/1.1\r\n" ..
        "Host: " .. ctx.host .. "\r\n" ..
        "Origin: https://attacker.example\r\n" ..
        "Connection: close\r\n\r\n"
    conn:send(req)
    local resp = conn:read(2000)
    conn:close()
    if not resp then return end

    local acao = resp:match("[Aa]ccess%-Control%-Allow%-Origin:%s*([%S]+)")
    if acao == "https://attacker.example" or acao == "*" then
        local cred = resp:lower():find("access%-control%-allow%-credentials:%s*true")
        sleipnir.add_finding{
            title = "CORS reflects arbitrary Origin",
            severity = cred and "high" or "medium",
            description =
                "The endpoint echoes an attacker-controlled Origin back in " ..
                "Access-Control-Allow-Origin" ..
                (cred and " together with Allow-Credentials: true" or "") ..
                ". A malicious site can read " ..
                (cred and "authenticated " or "") ..
                "responses on behalf of a visiting user.",
            evidence = "Origin: https://attacker.example -> ACAO: " .. acao,
            port = ctx.port,
        }
    end
end
