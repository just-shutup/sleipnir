#include "sleipnir/http_client.hpp"

namespace sln {

const std::string* HttpResponse::header(const std::string& lower_key) const {
    auto it = headers.find(lower_key);
    return it == headers.end() ? nullptr : &it->second;
}

// RFC 9112 §7.1: repeated "size\r\n data\r\n" chunks, terminated by a
// zero-size chunk and an optional trailer section. Chunk-size extensions
// after the ';' separator are ignored. Returns the decoded body; on a
// malformed or truncated stream returns whatever was decoded so far, which
// is enough for scanning purposes.
std::string decode_chunked(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    size_t pos = 0;
    for (;;) {
        size_t eol = in.find("\r\n", pos);
        if (eol == std::string::npos) break;
        size_t semi = in.find(';', pos);
        size_t size_end = (semi != std::string::npos && semi < eol) ? semi : eol;
        std::string hex = in.substr(pos, size_end - pos);
        // strip trailing spaces around the size token
        while (!hex.empty() && hex.front() == ' ') hex.erase(hex.begin());
        while (!hex.empty() && hex.back() == ' ') hex.pop_back();
        size_t size = 0;
        try {
            size = std::stoull(hex, nullptr, 16);
        } catch (...) {
            break; // not a chunk size: stop, keep what we have
        }
        pos = eol + 2;
        if (size == 0) break; // last chunk (trailer ignored: raw ends here)
        if (pos + size > in.size()) {
            out.append(in, pos, std::string::npos);
            break;
        }
        out.append(in, pos, size);
        pos += size;
        if (in.compare(pos, 2, "\r\n") == 0) pos += 2;
    }
    return out;
}

} // namespace sln
