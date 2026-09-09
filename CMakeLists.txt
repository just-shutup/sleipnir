cmake_minimum_required(VERSION 3.20)
project(sleipnir VERSION 0.3.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# third_party
# ---------------------------------------------------------------------------
# Asio (standalone) — header-only networking
add_library(asio INTERFACE)
target_include_directories(asio INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/asio/asio/include)
target_compile_definitions(asio INTERFACE ASIO_NO_DEPRECATED)

# Lua 5.4 — built from vendored sources
file(GLOB LUA_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lua/src/*.c)
list(FILTER LUA_SOURCES EXCLUDE REGEX "/(lua|luac|onelua)\\.c$")
add_library(lua54 STATIC ${LUA_SOURCES})
target_include_directories(lua54 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lua/src)
if(UNIX)
    target_link_libraries(lua54 PUBLIC m ${CMAKE_DL_LIBS})
endif()

# sol2 — header-only Lua bindings
add_library(sol2 INTERFACE)
target_include_directories(sol2 INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sol2/include)
target_link_libraries(sol2 INTERFACE lua54)

# nlohmann/json, CLI11, doctest — vendored single headers
add_library(vendor_headers INTERFACE)
target_include_directories(vendor_headers INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

# ---------------------------------------------------------------------------
# sleipnir library + CLI
# ---------------------------------------------------------------------------
add_subdirectory(libs/sleipnir)
add_subdirectory(apps/sleipnir)

# ---------------------------------------------------------------------------
# tests (BUILD_TESTS=ON)
# ---------------------------------------------------------------------------
option(BUILD_TESTS "Build unit tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
