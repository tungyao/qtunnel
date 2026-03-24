#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>

namespace proxy {

enum class LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3
};

inline std::atomic<int>& log_level_storage() {
    static std::atomic<int> level{static_cast<int>(LogLevel::Info)};
    return level;
}

inline void set_log_level(LogLevel level) {
    log_level_storage().store(static_cast<int>(level));
}

inline LogLevel current_log_level() {
    return static_cast<LogLevel>(log_level_storage().load());
}

inline bool should_log(LogLevel level) {
    return static_cast<int>(level) <= log_level_storage().load();
}

inline const char* log_level_name(LogLevel level) {
    switch (level) {
    case LogLevel::Error:
        return "error";
    case LogLevel::Warn:
        return "warn";
    case LogLevel::Info:
        return "info";
    case LogLevel::Debug:
        return "debug";
    default:
        return "info";
    }
}

inline bool parse_log_level(const std::string& text, LogLevel& level) {
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (lower == "error") {
        level = LogLevel::Error;
        return true;
    }
    if (lower == "warn" || lower == "warning") {
        level = LogLevel::Warn;
        return true;
    }
    if (lower == "info") {
        level = LogLevel::Info;
        return true;
    }
    if (lower == "debug") {
        level = LogLevel::Debug;
        return true;
    }
    return false;
}

inline void log_message(LogLevel level, const std::string& message) {
    if (!should_log(level)) {
        return;
    }
    std::ostream& os = (level == LogLevel::Error || level == LogLevel::Warn) ? std::cerr : std::cout;
    os << "[" << log_level_name(level) << "] " << message << "\n";
}

} // namespace proxy

#define PROXY_LOG(level, expr)                                                                        \
    do {                                                                                              \
        if (::proxy::should_log(::proxy::LogLevel::level)) {                                          \
            std::ostringstream proxy_log_stream__;                                                    \
            proxy_log_stream__ << expr;                                                               \
            ::proxy::log_message(::proxy::LogLevel::level, proxy_log_stream__.str());                \
        }                                                                                             \
    } while (0)
