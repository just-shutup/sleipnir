-- security_txt.lua: vulnerability disclosure policy presence (RFC 9116).
-- A /.well-known/security.txt tells researchers where to report findings;
-- its absence is informational but a marker of security maturity.
--
-- ctx: {host, port, service, ...}

function on_http_response(ctx)
    if ctx.service ~= "http" and ctx.service ~= "https" then return end
    if not ctx.http_status or ctx.http_status >= 500 then return end

    local resp = sleipnir.http_get(ctx.host, ctx.port,
                                   "/.well-known/security.txt")
    if not resp then return end

    if resp.status == 200 and resp.body:find("Contact:") then
        -- good practice: no finding, nothing to fix
        return
    end

    sleipnir.add_finding{
        title = "No security.txt (RFC 9116)",
        severity = "info",
        description =
            "The site does not publish /.well-known/security.txt with a " ..
            "Contact field. Researchers who find issues have no defined " ..
            "channel and may report elsewhere or not at all.",
        evidence = "GET /.well-known/security.txt -> " ..
            (resp.status or "no response"),
        port = ctx.port,
    }
end
