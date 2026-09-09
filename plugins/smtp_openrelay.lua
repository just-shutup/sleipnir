-- smtp_openrelay.lua — classic SMTP conversation to test for an open relay.
-- Demonstrates the raw TCP scripting API: connect, converse, report.

local RECIPIENT = "relaytest@example.com"

function on_service(ctx)
    if ctx.service ~= "smtp" then return end

    local conn = sleipnir.tcp_connect(ctx.host, ctx.port)
    if not conn then
        sleipnir.log("warn", "could not reconnect to SMTP port")
        return
    end

    local function read_reply()
        -- SMTP replies end with "<code> <text>\r\n" (space, not dash)
        local acc = conn:read(600) or ""
        if acc == "" then return nil end
        -- keep reading while the last reply line continues with '-'
        while true do
            local last_line = string.match(acc, "(%d%d%d.-)%r?%n$") or ""
            local cont = string.match(last_line, "^%d%d%d%-")
            if not cont then break end
            local more = conn:read(600)
            if not more or more == "" then break end
            acc = acc .. more
        end
        return acc
    end

    local banner = read_reply()
    if not banner then
        conn:close()
        sleipnir.log("info", "no SMTP banner read on " .. ctx.host)
        return
    end

    local ok = conn:send("HELO scanner.test\r\n") and
               read_reply() and
               conn:send("MAIL FROM:<probe@scanner.test>\r\n") and
               read_reply() and
               conn:send("RCPT TO:<" .. RECIPIENT .. ">\r\n")
    if not ok then
        conn:close()
        return
    end

    local reply = read_reply()
    conn:send("QUIT\r\n")
    conn:close()

    if not reply then return end

    local code = string.match(reply, "^(%d%d%d)")
    -- 250 = accepted (open relay), 251 = will forward
    if code == "250" or code == "251" then
        sleipnir.add_finding{
            title = "SMTP server may be an open relay",
            severity = "high",
            description = "RCPT TO for an external domain (" .. RECIPIENT ..
                ") was accepted. Open relays are abused for spam and " ..
                "phishing within hours of discovery.",
            evidence = "RCPT TO response: " .. reply,
        }
    else
        sleipnir.log("info", "not an open relay (RCPT -> " ..
            (code or "?") .. ")")
    end
end
