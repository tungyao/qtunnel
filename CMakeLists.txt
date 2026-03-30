cmake_minimum_required(VERSION 3.22)
project(proxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_definitions(-D_WIN32_WINNT=0x0601 -DWIN32_LEAN_AND_MEAN -DNOMINMAX)
else()
endif()

set(COMMON_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
set(ENABLE_APP OFF CACHE BOOL "" FORCE)
set(ENABLE_HPACK_TOOLS OFF CACHE BOOL "" FORCE)
set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ENABLE_DOC OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)

include(FetchContent)
set(BORINGSSL_GIT_REPOSITORY "https://github.com/google/boringssl.git" CACHE STRING "BoringSSL Git repository")
set(BORINGSSL_GIT_TAG "aa0acca1acf36b7fb16aa8a7b60b97d5cb01404d" CACHE STRING "Pinned BoringSSL commit to fetch")
set(BORINGSSL_ALLOW_CXX_RUNTIME ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    boringssl
    GIT_REPOSITORY ${BORINGSSL_GIT_REPOSITORY}
    GIT_TAG ${BORINGSSL_GIT_TAG}
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(boringssl)

set(NGHTTP2_GIT_REPOSITORY "https://github.com/nghttp2/nghttp2.git" CACHE STRING "nghttp2 Git repository")
set(NGHTTP2_GIT_TAG "v1.68.1" CACHE STRING "Pinned nghttp2 tag or commit to fetch")
FetchContent_Declare(
    nghttp2
    GIT_REPOSITORY ${NGHTTP2_GIT_REPOSITORY}
    GIT_TAG ${NGHTTP2_GIT_TAG}
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(nghttp2)

set(HOMEPAGE_HTML_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/code.html)
set(HOMEPAGE_HTML_HEADER ${GENERATED_INCLUDE_DIR}/homepage_html.h)

add_custom_command(
    OUTPUT ${HOMEPAGE_HTML_HEADER}
    COMMAND ${CMAKE_COMMAND}
            -DINPUT_FILE=${HOMEPAGE_HTML_INPUT}
            -DOUTPUT_FILE=${HOMEPAGE_HTML_HEADER}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/generate_homepage_header.cmake
    DEPENDS ${HOMEPAGE_HTML_INPUT} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/generate_homepage_header.cmake
    COMMENT "Generating homepage_html.h from code.html"
    VERBATIM
)

add_custom_target(generate_homepage_header DEPENDS ${HOMEPAGE_HTML_HEADER})

add_executable(server
    src/server.cpp
    ${HOMEPAGE_HTML_HEADER}
)
add_dependencies(server generate_homepage_header)
target_include_directories(server PRIVATE ${COMMON_INCLUDE_DIR} ${GENERATED_INCLUDE_DIR})

add_executable(client
    src/client.cpp
)
target_include_directories(client PRIVATE ${COMMON_INCLUDE_DIR})

if(MSVC)
    target_compile_options(server PRIVATE
        /W4
        /EHsc
        /permissive-
        /utf-8
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:RelWithDebInfo>:/O2>
        $<$<CONFIG:MinSizeRel>:/O1>
    )
    target_compile_options(client PRIVATE
        /W4
        /EHsc
        /permissive-
        /utf-8
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:RelWithDebInfo>:/O2>
        $<$<CONFIG:MinSizeRel>:/O1>
    )
else()
    target_compile_options(server PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter -Os)
    target_compile_options(client PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter -Os)
endif()

set(PROXY_TLS_LIBRARIES nghttp2_static)
if(WIN32)
    list(APPEND PROXY_TLS_LIBRARIES ws2_32)
else()
    list(APPEND PROXY_TLS_LIBRARIES pthread)
endif()

add_library(proxy_tls_ssl INTERFACE)
target_link_libraries(proxy_tls_ssl INTERFACE ssl crypto)

target_link_libraries(server PRIVATE proxy_tls_ssl ${PROXY_TLS_LIBRARIES})
target_link_libraries(client PRIVATE proxy_tls_ssl ${PROXY_TLS_LIBRARIES})
