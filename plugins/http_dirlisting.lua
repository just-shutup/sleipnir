-- http_dirlisting.lua — detect open directory indexes on non-root paths.
-- Runs for every HTTP response the engine collects.

local LOOKS_LIKE_LISTING = {
    "Index of /",
    "Directory listing for",
    "Parent Directory",
}

function on_http_response(ctx)
    -- the engine already reports listing on "/", here we check common dirs
    local paths = { "/uploads/", "/files/", "/static/", "/backup/", "/tmp/" }

    for _, path in ipairs(paths) do
        local resp = sleipnir.http_get(ctx.host, ctx.port, path)
        if resp and resp.status == 200 and resp.body then
            for _, marker in ipairs(LOOKS_LIKE_LISTING) do
                if string.find(resp.body, marker, 1, true) then
                    sleipnir.add_finding{
                        title = "Directory listing on " .. path,
                        severity = "medium",
                        description = "The path " .. path ..
                            " returns an auto-generated file index; " ..
                            "visitors can enumerate and download files.",
                        evidence = "GET " .. path .. " -> " ..
                            resp.status .. ", contains marker: " .. marker,
                    }
                    break
                end
            end
        end
    end
end
