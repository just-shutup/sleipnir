-- http_admin_panels.lua — probe a wider list of admin/management panels.
-- Complements the built-in check with paths that are common in real audits.

local PATHS = {
    { path = "/wp-admin/",            title = "WordPress admin panel",      marker = "wp-admin" },
    { path = "/administrator/",       title = "Joomla admin panel",         marker = "Joomla" },
    { path = "/manager/html",         title = "Tomcat manager exposed",     marker = "Tomcat Web Application Manager" },
    { path = "/jenkins/",             title = "Jenkins exposed",            marker = "Jenkins" },
    { path = "/kibana/",              title = "Kibana exposed",             marker = "kibana" },
    { path = "/grafana/",             title = "Grafana exposed",            marker = "grafana" },
    { path = "/solr/",                title = "Solr admin exposed",         marker = "Solr Admin" },
    { path = "/actuator",             title = "Spring Boot actuator",       marker = "whitelabel" },
}

function on_http_response(ctx)
    for _, p in ipairs(PATHS) do
        local resp = sleipnir.http_get(ctx.host, ctx.port, p.path)
        if resp and resp.status == 200 and resp.body then
            if string.find(resp.body, p.marker, 1, true) then
                sleipnir.add_finding{
                    title = p.title .. " reachable at " .. p.path,
                    severity = "low",
                    description = "A management interface is reachable " ..
                        "without authentication. Expect brute-force and " ..
                        "known-CVE attacks against it.",
                    evidence = "GET " .. p.path .. " -> " .. resp.status,
                }
            end
        end
    end
end
