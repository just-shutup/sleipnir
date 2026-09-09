-- redis_unauth.lua: unauthenticated Redis access check.
-- An INFO command that succeeds without AUTH means every key in the
-- instance (and often RCE via EVAL/Lua CVEs) is reachable by anyone.
--
-- ctx: {host, port, service, product, version, banner}

function on_port_open(ctx)
    if ctx.service ~= "redis" then return end

    local conn = sleipnir.tcp_connect(ctx.host, ctx.port)
    if not conn then return end

    conn:send("INFO server\r\n")
    local resp = conn:read(1500)
    conn:close()
    if not resp then return end

    local version = resp:match("redis_version:([%d%.]+)")
    if version then
        sleipnir.add_finding{
            title = "Redis accessible without authentication",
            severity = "critical",
            description =
                "The INFO command succeeded without AUTH: the whole dataset " ..
                "is exposed. Redis also offers EVAL (Lua), which on many " ..
                "builds converts this into remote code execution.",
            evidence = "INFO server -> redis_version " .. version,
            port = ctx.port,
        }
    end
end
