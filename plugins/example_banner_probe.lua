-- example_banner_probe.lua — minimal plugin template.
-- Copies the plugin skeleton used by new checks; kept simple on purpose so
-- it doubles as documentation of the plugin API.

function on_port_open(ctx)
    sleipnir.log("info", "port open: " .. ctx.host .. ":" .. ctx.port ..
        (ctx.service ~= "" and (" (" .. ctx.service .. ")") or ""))
end

function on_service(ctx)
    -- example: flag FTP servers that allow anonymous login
    if ctx.service == "ftp" then
        local conn = sleipnir.tcp_connect(ctx.host, ctx.port)
        if conn then
            conn:read(500) -- banner
            conn:send("USER anonymous\r\n")
            conn:read(500) -- 331 password required
            conn:send("PASS sleipnir@example.com\r\n")
            local resp = conn:read(500) or ""
            conn:send("QUIT\r\n")
            conn:close()
            if string.find(resp, "230", 1, true) then
                sleipnir.add_finding{
                    title = "FTP anonymous login enabled",
                    severity = "medium",
                    description = "The FTP server accepts the anonymous " ..
                        "user without a password.",
                    evidence = "USER anonymous -> " .. resp,
                }
            end
        end
    end
end
