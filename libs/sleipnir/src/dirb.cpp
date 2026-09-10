#include "sleipnir/dirb.hpp"

#include <fstream>

namespace sln {

const std::vector<std::string>& builtin_wordlist() {
    static const std::vector<std::string> words = {
        "admin",       "admin.php",    "administrator", "manager",
        "panel",       "dashboard",    "console",       "cpanel",
        "phpmyadmin",  "adminer",      "backup",        "backups",
        "bak",         "old",          "new",           "test",
        "temp",        "tmp",          "dev",           "internal",
        "private",     "secret",       "secrets",       "conf",
        "config",      "configs",      "configuration", ".git",
        ".svn",        ".hg",          ".DS_Store",     ".env.backup",
        "db",          "dump",         "sql",           "data",
        "files",       "file",         "uploads",       "upload",
        "media",       "assets",       "static",        "api",
        "api/v1",      "swagger",      "docs",          "doc",
        "info.php",    "phpinfo.php",  "server-status", "server-info",
        "actuator",    "metrics",      "health",        "debug",
        "monitor",     "jenkins",      "grafana",       "kibana",
        "wp-admin",    "wp-login.php", "wp-content",    "xmlrpc.php",
        "composer.json", "composer.lock", "package-lock.json", "yarn.lock",
        "Dockerfile",  "docker-compose.yml", "Makefile", "web.config",
        "vendor",      "node_modules", "cgi-bin",       "shell",
        "login",       "signin",       "register",      "account",
        "user",        "users",        "profile",       "graphql",
        "index.bak",   "dump.sql",     "site.zip",      "backup.zip",
    };
    return words;
}

std::vector<std::string> load_wordlist(const std::string& path) {
    if (path.empty()) return builtin_wordlist();
    std::ifstream in(path);
    if (!in) return builtin_wordlist();
    std::vector<std::string> words;
    std::string line;
    while (std::getline(in, line)) {
        size_t hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        size_t b = line.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) continue;
        size_t e = line.find_last_not_of(" \t\r\n");
        std::string word = line.substr(b, e - b + 1);
        if (!word.empty() && word.front() == '/') word.erase(0, 1);
        if (!word.empty()) words.push_back(word);
    }
    if (words.empty()) return builtin_wordlist();
    return words;
}

} // namespace sln
