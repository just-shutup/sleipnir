#include "sleipnir/plugins.hpp"
#include "sleipnir/http_client.hpp"
#include "sleipnir/netio.hpp"
#include "sleipnir/results.hpp"

#ifdef SLEIPNIR_HAVE_TLS
#include "sleipnir/tls_checks.hpp"
#include "sleipnir/tls_client.hpp"
#endif

#include <sol/sol.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <mutex>

namespace sln {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Lua-facing connection wrapper
// ---------------------------------------------------------------------------

struct LuaConn {
    TcpClient client;
    explicit LuaConn(asio::io_context& io) : client(io) {}
};

namespace {

sol::object lua_nil(sol::this_state ts) {
    return sol::make_object(sol::state_view(ts), sol::nil);
}

// ---------------------------------------------------------------------------
// Restricted plugin environment: stdlib basics + our API, no io/os.execute/
// require/dofile. Convenience hardening, not a true sandbox.
// ---------------------------------------------------------------------------
sol::table make_safe_env(sol::this_state ts) {
    sol::state_view lua(ts);
    sol::table env = lua.create_table();

    static const char* safe_globals[] = {
        "string", "table", "math", "utf8", "ipairs", "pairs", "next",
        "tostring", "tonumber", "type", "select", "pcall", "xpcall", "error",
        "assert", "setmetatable", "getmetatable", "rawget", "rawset",
        "rawequal", "rawlen", "_VERSION"};
    for (const char* name : safe_globals) {
        sol::object g = lua[name];
        if (g.valid()) env[name] = g;
    }
    // trimmed os: only timing, no filesystem/process access
    sol::table os_full = lua["os"];
    if (os_full.valid()) {
        sol::table os_safe = lua.create_table();
        if (os_full["time"].valid()) os_safe["time"] = os_full["time"];
        if (os_full["clock"].valid()) os_safe["clock"] = os_full["clock"];
        if (os_full["date"].valid()) os_safe["date"] = os_full["date"];
        env["os"] = os_safe;
    }
    env["_G"] = env;

    sol::table mt = lua.create_table();
    mt["__index"] = [](sol::table, const std::string& key) -> sol::object {
        throw std::runtime_error("global '" + key +
                                 "' is not available in the plugin sandbox");
    };
    env[sol::metatable_key] = mt;
    return env;
}
// Loads `code` as a Lua chunk whose _ENV upvalue points at `env`.
sol::protected_function load_plugin_script(sol::state& lua,
                                           const std::string& code,
                                           const std::string& chunk_name,
                                           const sol::object& env) {
    sol::load_result loaded = lua.load_buffer(
        code.c_str(), code.size(), chunk_name.c_str(), sol::load_mode::text);
    if (!loaded.valid()) return sol::protected_function();

    sol::function fn = loaded.get<sol::function>();
    lua_State* L = lua.lua_state();
    fn.push(); // stack: [fn]
    if (lua_getupvalue(L, -1, 1) != nullptr) { // stack: [fn, old_env]
        env.push();                            // stack: [fn, old_env, new_env]
        lua_setupvalue(L, -3, 1);              // sets _ENV, pops new_env
        lua_pop(L, 1);                         // pop old_env -> [fn]
    }
    sol::protected_function result(L, -1);
    lua_pop(L, 1);
    return result;
}

void register_api(PluginHost::Plugin& p, sol::state& lua, sol::table& api) {
    lua.new_usertype<LuaConn>(
        "TcpConn",                                                     //
        "send", [](LuaConn& c, const std::string& data) {              //
            return c.client.send(data);
        },                                                             //
        "read",
        [](LuaConn& c, sol::this_state ts, int wait_ms) -> sol::object {
            std::string data = c.client.recv_all(wait_ms, wait_ms);
            if (data.empty()) return lua_nil(ts);
            return sol::make_object(sol::state_view(ts), data);
        },                                                             //
        "close", [](LuaConn& c) { c.client.close(); });

    api["tcp_connect"] = [&p](const std::string& host, int port) -> sol::object {
        auto conn = std::make_shared<LuaConn>(*p.io);
        if (!conn->client.connect(host, static_cast<uint16_t>(port),
                                  p.timeout_ms))
            return sol::make_object(*p.lua, sol::nil);
        return sol::make_object(*p.lua, conn);
    };

    api["http_get"] = [&p](const std::string& host, int port,
                           const std::string& path) -> sol::object {
        TcpClient client(*p.io);
        auto resp = http_get(client, host, static_cast<uint16_t>(port), path,
                             p.timeout_ms);
        if (!resp) return sol::make_object(*p.lua, sol::nil);
        sol::table t = p.lua->create_table();
        t["status"] = resp->status;
        sol::table headers = p.lua->create_table();
        for (const auto& [k, v] : resp->headers) headers[k] = v;
        t["headers"] = headers;
        t["body"] = resp->body;
        return t;
    };

#ifdef SLEIPNIR_HAVE_TLS
    api["https_get"] = [&p](const std::string& host, int port,
                            const std::string& path) -> sol::object {
        TlsClient client(*p.io);
        auto resp = http_get(client, host, static_cast<uint16_t>(port), path,
                             p.timeout_ms);
        if (!resp) return sol::make_object(*p.lua, sol::nil);
        sol::table t = p.lua->create_table();
        t["status"] = resp->status;
        sol::table headers = p.lua->create_table();
        for (const auto& [k, v] : resp->headers) headers[k] = v;
        t["headers"] = headers;
        t["body"] = resp->body;
        return t;
    };

    api["tls_info"] = [&p](const std::string& host, int port) -> sol::object {
        TlsClient client(*p.io);
        if (!client.connect(host, static_cast<uint16_t>(port), p.timeout_ms))
            return sol::make_object(*p.lua, sol::nil);
        TlsInfo info = summarize_tls(host, client.peer());
        sol::table t = p.lua->create_table();
        t["protocol"] = info.protocol;
        t["cipher"] = info.cipher;
        t["subject"] = info.subject;
        t["issuer"] = info.issuer;
        t["not_before"] = info.not_before;
        t["not_after"] = info.not_after;
        t["self_signed"] = info.self_signed;
        t["chain_trusted"] = info.chain_trusted;
        t["hostname_match"] = info.hostname_match;
        return t;
    };
#endif

    api["add_finding"] = [&p](sol::table f) {
        Finding finding;
        finding.host = p.ctx_host;
        finding.port = f.get_or<std::uint16_t>("port", 0);
        if (finding.port == 0) finding.port = p.ctx_port;
        finding.title = f.get_or<std::string>("title", "untitled");
        finding.severity =
            severity_from_string(f.get_or<std::string>("severity", "info"));
        finding.description = f.get_or<std::string>("description", "");
        finding.evidence = f.get_or<std::string>("evidence", "");
        finding.cve = f.get_or<std::string>("cve", "");
        finding.source = "plugin:" + p.name;
        // A plugin finding with evidence actively demonstrated the issue;
        // without evidence it stays an unverified suspicion.
        finding.verified = !finding.evidence.empty();
        finding.confidence = finding.verified ? "confirmed" : "potential";
        p.findings->push_back(std::move(finding));
    };

    api["log"] = [&p](sol::variadic_args va) {
        std::string msg;
        lua_State* L = va.lua_state();
        for (const auto& handle : va) {
            sol::object o = handle;
            o.push(L);
            size_t len = 0;
            const char* s = lua_tolstring(L, -1, &len);
            if (s) msg.append(s, len);
            lua_pop(L, 1);
        }
        p.out->log("[lua:" + p.name + "] " + msg);
    };
}

} // namespace

PluginHost::~PluginHost() = default;

PluginHost::ScriptCheckResult PluginHost::run_check_script(
    const std::string& path, const std::string& host, uint16_t port,
    asio::io_context& io, int timeout_ms, ResultCollector& out) {
    ScriptCheckResult result;
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        result.error = "check script not found: " + path;
        return result;
    }

    // A throwaway plugin state: same sandbox and API as hook plugins, but
    // driven by the verify(ctx) entry point instead of scan hooks.
    Plugin p;
    p.name = fs::path(path).filename().string();
    p.lua = std::make_unique<sol::state>();
    sol::state& lua = *p.lua;
    lua.open_libraries(sol::lib::base, sol::lib::string, sol::lib::table,
                       sol::lib::math, sol::lib::os, sol::lib::utf8);
    p.io = &io;
    p.timeout_ms = timeout_ms;
    p.out = &out;
    std::vector<Finding> sink; // add_finding from a check is ignored
    p.findings = &sink;
    p.ctx_host = host;
    p.ctx_port = port;

    try {
        std::ifstream in(path);
        if (!in) throw std::runtime_error("cannot open file");
        std::string code((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());

        sol::table env = make_safe_env(lua.lua_state());
        sol::table api = lua.create_table();
        env["sleipnir"] = api;
        register_api(p, lua, api);

        sol::protected_function chunk =
            load_plugin_script(lua, code, p.name, env);
        if (!chunk.valid()) throw std::runtime_error("syntax error");
        auto loaded = chunk();
        if (!loaded.valid())
            throw std::runtime_error(std::string("load error: ") +
                                     loaded.get<sol::error>().what());

        sol::object fn_obj = env.raw_get<sol::object>(std::string("verify"));
        if (!fn_obj.valid())
            throw std::runtime_error("no verify(ctx) function defined");
        sol::protected_function fn = fn_obj;

        sol::table ctx = lua.create_table();
        ctx["host"] = host;
        ctx["port"] = port;
        ctx["timeout"] = timeout_ms;

        auto res = fn(ctx);
        if (!res.valid())
            throw std::runtime_error(std::string("verify error: ") +
                                     res.get<sol::error>().what());
        sol::object ret = res;
        if (ret.is<sol::table>()) {
            sol::table t = ret;
            result.verified = t.get_or("verified", false);
            result.evidence = t.get_or<std::string>("evidence", "");
        } else if (ret.is<bool>()) {
            result.verified = ret.as<bool>();
        }
    } catch (const std::exception& e) {
        result.error = e.what();
        result.verified = false;
    }
    return result;
}

std::vector<PluginHost::LoadReport> PluginHost::load_dir(const std::string& dir) {
    std::vector<LoadReport> reports;
    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) return reports;

    std::vector<fs::path> files;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (entry.path().extension() == ".lua") files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());

    for (const auto& file : files) {
        LoadReport rep;
        rep.plugin = file.filename().string();

        auto plugin = std::make_unique<Plugin>();
        plugin->name = rep.plugin;
        plugin->lua = std::make_unique<sol::state>();
        sol::state& lua = *plugin->lua;
        lua.open_libraries(sol::lib::base, sol::lib::string, sol::lib::table,
                           sol::lib::math, sol::lib::os, sol::lib::utf8);

        try {
            std::ifstream in(file);
            if (!in) throw std::runtime_error("cannot open file");
            std::string code((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());

            sol::table env = make_safe_env(lua.lua_state());

            sol::table api = lua.create_table();
            env["sleipnir"] = api;
            register_api(*plugin, lua, api);

            sol::protected_function chunk =
                load_plugin_script(lua, code, rep.plugin, env);
            if (!chunk.valid())
                throw std::runtime_error("syntax error");

            sol::protected_function_result res = chunk();
            if (!res.valid())
                throw std::runtime_error(std::string("load error: ") +
                                         res.get<sol::error>().what());

            lua.globals()["__env"] = env; // keep the env table alive
            plugins_.push_back(std::move(plugin));
        } catch (const std::exception& e) {
            rep.error = e.what();
        }
        reports.push_back(std::move(rep));
    }
    return reports;
}

std::vector<std::string> PluginHost::names() const {
    std::vector<std::string> out;
    for (const auto& p : plugins_) out.push_back(p->name);
    return out;
}

void PluginHost::dispatch(Plugin& p, const char* hook, const PluginContext& ctx,
                          asio::io_context& io, int timeout_ms,
                          ResultCollector& out) {
    std::lock_guard<std::mutex> lock(p.mutex);
    sol::state& lua = *p.lua;
    sol::object env_obj = lua.globals()["__env"];
    if (!env_obj.valid()) return;
    sol::table env = env_obj;
    // raw_get bypasses the sandbox __index metamethod, which throws on
    // unknown keys; a plugin simply may not define this hook.
    sol::object fn_obj = env.raw_get<sol::object>(std::string(hook));
    if (!fn_obj.valid()) return;
    sol::protected_function fn = fn_obj;

    std::vector<Finding> local_findings;
    p.io = &io;
    p.timeout_ms = timeout_ms;
    p.out = &out;
    p.findings = &local_findings;
    p.ctx_host = ctx.host;
    p.ctx_port = ctx.port;

    sol::table t = lua.create_table();
    t["host"] = ctx.host;
    t["port"] = ctx.port;
    t["service"] = ctx.service;
    t["product"] = ctx.product;
    t["version"] = ctx.version;
    t["banner"] = ctx.banner;
    if (ctx.has_http) {
        t["http_status"] = ctx.http_status;
        sol::table headers = lua.create_table();
        for (const auto& [k, v] : ctx.http_headers) headers[k] = v;
        t["http_headers"] = headers;
        t["http_body"] = ctx.http_body;
    }

    sol::protected_function_result res = fn(t);
    if (!res.valid()) {
        out.log("[plugin error] " + p.name + "/" + hook + ": " +
                res.get<sol::error>().what());
    }
    for (auto& f : local_findings) out.add_finding(std::move(f));
}

void PluginHost::on_port_open(const PluginContext& ctx, asio::io_context& io,
                              int timeout_ms, ResultCollector& out) {
    for (auto& p : plugins_)
        dispatch(*p, "on_port_open", ctx, io, timeout_ms, out);
}

void PluginHost::on_service(const PluginContext& ctx, asio::io_context& io,
                            int timeout_ms, ResultCollector& out) {
    for (auto& p : plugins_)
        dispatch(*p, "on_service", ctx, io, timeout_ms, out);
}

void PluginHost::on_http_response(const PluginContext& ctx,
                                  asio::io_context& io, int timeout_ms,
                                  ResultCollector& out) {
    for (auto& p : plugins_)
        dispatch(*p, "on_http_response", ctx, io, timeout_ms, out);
}

} // namespace sln
