-- docker_api_unauth.lua: Docker Engine API reachable without TLS or
-- authentication. The API equals root on the host: /containers, /exec,
-- image mounting of the filesystem.
--
-- ctx: {host, port, service, ...}

function on_port_open(ctx)
    if ctx.service ~= "http" then return end
    -- Docker is normally on 2375 (plain) / 2376 (TLS); avoid poking every
    -- web server we meet.
    if ctx.port ~= 2375 and ctx.port ~= 2376 then return end

    local resp = sleipnir.http_get(ctx.host, ctx.port, "/version")
    if not resp or not resp.body then return end

    local api = resp.body:match('"ApiVersion"%s*:%s*"([%d%.]+)"')
    if api then
        sleipnir.add_finding{
            title = "Docker Engine API exposed without authentication",
            severity = "critical",
            description =
                "The Docker Engine HTTP API answers without TLS or auth. " ..
                "API access is equivalent to root on the container host " ..
                "(privileged containers, host filesystem mounts, /exec).",
            evidence = "GET /version -> ApiVersion " .. api,
            port = ctx.port,
        }
    end
end
