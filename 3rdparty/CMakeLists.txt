cmake_policy(SET CMP0135 NEW)
include(FetchContent)

if (NOT JEVITERM_HOMEBREW_DEPS)
    option(protobuf_INSTALL OFF)
    option(protobuf_BUILD_TESTS OFF)
    option(protobuf_BUILD_SHARED_LIBS OFF)
    option(ABSL_ENABLE_INSTALL OFF)
    option(ABSL_PROPAGATE_CXX_STD ON)
    add_subdirectory(protobuf)
    include(${CMAKE_CURRENT_SOURCE_DIR}/protobuf/cmake/protobuf-generate.cmake)

    if (NOT JEVITERM_DETERMINISTIC)
        set(JSON_HPP_URL https://github.com/nlohmann/json/raw/develop/single_include/nlohmann/json.hpp)
    else()
        set(JSON_HPP_URL https://github.com/nlohmann/json/raw/v3.11.2/single_include/nlohmann/json.hpp)
    endif()

    FetchContent_Declare(
        nlohmann_json_fetch
        FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
        DOWNLOAD_NO_EXTRACT TRUE
        URL ${JSON_HPP_URL}
    )
    FetchContent_MakeAvailable(nlohmann_json_fetch)
    FetchContent_GetProperties(nlohmann_json_fetch SOURCE_DIR JSON_HPP_SRC_DIR)

    add_library(nlohmann_json INTERFACE)
    target_include_directories(nlohmann_json INTERFACE ${JSON_HPP_SRC_DIR})

else()

    find_package(protobuf CONFIG REQUIRED)
    find_package(nlohmann_json REQUIRED)

endif()

if (NOT JEVITERM_DETERMINISTIC)
    set(ITERM_PROTOBUF_URL https://github.com/gnachman/iTerm2/raw/master/proto/api.proto)
else()
    set(ITERM_PROTOBUF_URL https://github.com/gnachman/iTerm2/raw/v20231011-nightly/proto/api.proto)
endif()

FetchContent_Declare(
    iterm2-protobuf
    FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
    DOWNLOAD_NO_EXTRACT TRUE
    URL ${ITERM_PROTOBUF_URL}
)
FetchContent_MakeAvailable(iterm2-protobuf)
FetchContent_GetProperties(iterm2-protobuf SOURCE_DIR ITERM2_PROTOBUF_SRC_DIR)

add_custom_command(OUTPUT
    ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto
    COMMAND ${CMAKE_COMMAND} -E copy ${ITERM2_PROTOBUF_SRC_DIR}/api.proto ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto
    DEPENDS ${ITERM2_PROTOBUF_SRC_DIR}/api.proto
)

# add_custom_command(OUTPUT
#     ${CMAKE_CURRENT_BINARY_DIR}/iterm-api-proto/iterm-api.pb.cc
#     ${CMAKE_CURRENT_BINARY_DIR}/iterm-api-proto/iterm-api.pb.h
#     COMMAND $<TARGET_FILE:protobuf::protoc> --cpp_out=code_size:${CMAKE_CURRENT_BINARY_DIR}/iterm-api --proto_path ${protobuf_SOURCE_DIR}/src --proto_path ${ITERM2_PROTOBUF_SRC_DIR} ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto
#     DEPENDS ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto
# )

add_library(iterm-api-proto OBJECT ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto)
target_link_libraries(iterm-api-proto PUBLIC protobuf::libprotobuf)
target_include_directories(iterm-api-proto PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/iterm-api-proto)
protobuf_generate(
    TARGET iterm-api-proto
    IMPORT_DIRS ${ITERM2_PROTOBUF_SRC_DIR}
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/iterm-api-proto)