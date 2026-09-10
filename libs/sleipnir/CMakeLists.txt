add_library(sleipnir STATIC
    src/targets.cpp
    src/types.cpp
    src/netio.cpp
    src/syn_scan.cpp
    src/udp_scan.cpp
    src/tls_client.cpp
    src/tls_checks.cpp
    src/version.cpp
    src/cve_db.cpp
    src/probes.cpp
    src/http_client.cpp
    src/checks.cpp
    src/crawler.cpp
    src/plugins.cpp
    src/fuzz.cpp
    src/verify.cpp
    src/engine.cpp
    src/report.cpp
)

target_include_directories(sleipnir PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(sleipnir PRIVATE SLEIPNIR_VERSION="${PROJECT_VERSION}")

# TLS support (asio::ssl + OpenSSL). Optional at build time: when no OpenSSL
# development files are found, the scanner still builds and simply skips
# TLS-based checks; SLEIPNIR_HAVE_TLS gates the implementation.
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    message(STATUS "TLS support enabled (OpenSSL ${OPENSSL_VERSION})")
    target_compile_definitions(sleipnir PUBLIC SLEIPNIR_HAVE_TLS=1)
    target_link_libraries(sleipnir PUBLIC OpenSSL::SSL OpenSSL::Crypto)
else()
    message(STATUS "OpenSSL not found — building without TLS support")
endif()

target_link_libraries(sleipnir
    PUBLIC
        asio
        sol2
        vendor_headers
        Threads::Threads
)

if(UNIX)
    find_library(DL_LIB dl)
    if(DL_LIB)
        target_link_libraries(sleipnir PUBLIC ${DL_LIB})
    endif()
endif()
