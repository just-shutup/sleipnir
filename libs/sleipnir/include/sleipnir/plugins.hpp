// Lua plugin host. Each plugin is a .lua file loaded into its own lua_State
// with a restricted environment (no io, os.execute, require, ...). Plugins
// register hook functions that the engine calls as it scans:
//
//   function on_port_open(ctx) ... end
//   function on_service(ctx)  ... end    -- after fingerprinting
//   function on_http_response(ctx) ... end
//
// ctx = {host, port, service, product, version, banner,
//        http_status, http_headers, http_body}
//
// Plugin API (global table `sleipnir`):
//   sleipnir.tcp_connect(host, port)          -> conn or nil, err
//   conn:send(data)                           -> bool
//   conn:read(wait_ms)                        -> string or nil
//   conn:close()
//   sleipnir.http_get(host, port, path)       -> {status=, headers=, body=} or nil
//   sleipnir.add_finding{title=, severity=, description=, evidence=}
//   sleipnir.log(msg...)                      -> concatenated to the log
#pragma once

#include "sleipnir/types.hpp"

#include <asio.hpp>
#include <sol/sol.hpp>

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace sln {

struct PluginContext {
    std::string host;
    uint16_t port = 0;
    std::string service;
    std::string product;
    std::string version;
    std::string banner;
    bool has_http = false;
    int http_status = 0;
    std::map<std::string, std::string> http_headers;
    std::string http_body;
};

class ResultCollector;

class PluginHost {
public:
    struct LoadReport {
        std::string plugin;
        std::string error; // empty on success
    };

    struct Plugin {
        std::string name;
        std::unique_ptr<sol::state> lua;
        std::mutex mutex; // serializes hook calls into this plugin's lua_State

        // per-dispatch call environment read by the API closures
        asio::io_context* io = nullptr;
        int timeout_ms = 0;
        ResultCollector* out = nullptr;
        std::vector<Finding>* findings = nullptr;
        std::string ctx_host;
        uint16_t ctx_port = 0;
    };

    ~PluginHost(); // out-of-line: Plugin is incomplete in this header

    // Result of a script-based CVE check (plugins/checks/*.lua). The script
    // defines `function verify(ctx)` with ctx = {host, port, timeout} and
    // returns {verified=bool, evidence=string}; it may use the same
    // sandboxed API as hook plugins (tcp_connect, http_get, ...).
    struct ScriptCheckResult {
        bool verified = false;
        std::string evidence;
        std::string error; // load/runtime error; empty on success
    };

    // Loads and runs a check script on demand. Never throws: failures come
    // back as error text in the result.
    ScriptCheckResult run_check_script(const std::string& path,
                                       const std::string& host, uint16_t port,
                                       asio::io_context& io, int timeout_ms,
                                       ResultCollector& out);

    // Loads every .lua file in dir (non-recursive). Missing dir is not an
    // error (plugins are optional).
    std::vector<LoadReport> load_dir(const std::string& dir);

    size_t count() const { return plugins_.size(); }
    std::vector<std::string> names() const;

    // Hook dispatch: no-ops for plugins that did not define the hook.
    // Calls are serialized per plugin (one lua_State per plugin).
    void on_port_open(const PluginContext& ctx, asio::io_context& io,
                      int timeout_ms, ResultCollector& out);
    void on_service(const PluginContext& ctx, asio::io_context& io,
                    int timeout_ms, ResultCollector& out);
    void on_http_response(const PluginContext& ctx, asio::io_context& io,
                          int timeout_ms, ResultCollector& out);

private:
    void dispatch(Plugin& p, const char* hook, const PluginContext& ctx,
                  asio::io_context& io, int timeout_ms, ResultCollector& out);

    std::vector<std::unique_ptr<Plugin>> plugins_;
};

} // namespace sln
