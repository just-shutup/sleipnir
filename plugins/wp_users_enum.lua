-- wp_users_enum.lua: WordPress REST API user enumeration. When the front
-- page looks like WordPress, the /wp-json/wp/v2/users endpoint often
-- returns logins without authentication — a prepared user list for
-- password attacks.
--
-- ctx: {host, port, service, http_status, http_body, ...}

function on_http_response(ctx)
    if ctx.service ~= "http" and ctx.service ~= "https" then return end
    if not ctx.http_body then return end
    -- only probe when the front page is actually WordPress
    if not ctx.http_body:find("wp%-content") and
       not ctx.http_body:find("wp%-json") then
        return
    end

    local resp = sleipnir.http_get(ctx.host, ctx.port, "/wp-json/wp/v2/users")
    if not resp or resp.status ~= 200 or not resp.body then return end

    local users = {}
    for slug in resp.body:gmatch('"slug"%s*:%s*"([^"]+)"') do
        users[#users + 1] = slug
        if #users >= 10 then break end
    end
    if #users == 0 then return end

    local list = table.concat(users, ", ")
    sleipnir.add_finding{
        title = "WordPress users enumerable via REST API",
        severity = "medium",
        description =
            "The REST API discloses registered user logins (" ..
            #users .. " shown). The list is a ready input for credential " ..
            "attacks against wp-login.php.",
        evidence = "GET /wp-json/wp/v2/users -> logins: " .. list,
        port = ctx.port,
    }
end
