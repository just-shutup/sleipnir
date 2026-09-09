-- smtp_vrfy.lua: VRFY command enabled. VRFY turns an SMTP server into a
-- username oracle: the response distinguishes existing mailboxes from
-- nonexistent ones, feeding password attacks.
--
-- ctx: {host, port, service, ...}

function on_port_open(ctx)
    if ctx.service ~= "smtp" then return end

    local conn = sleipnir.tcp_connect(ctx.host, ctx.port)
    if not conn then return end

    conn:read(1200)                                  -- banner
    conn:send("VRFY root\r\n")
    local resp = conn:read(1200)
    conn:send("QUIT\r\n")
    conn:close()
    if not resp then return end

    local code = resp:match("^(%d%d%d)")
    if code == "250" or code == "251" or code == "252" then
        sleipnir.add_finding{
            title = "SMTP VRFY command enabled",
            severity = "medium",
            description =
                "The server confirms mailbox existence via VRFY (code " ..
                code .. "). An attacker can enumerate valid usernames " ..
                "before attempting passwords.",
            evidence = "VRFY root -> " .. resp:sub(1, 40),
            port = ctx.port,
        }
    end
end
