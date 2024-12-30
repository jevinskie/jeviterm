cmake_policy(SET CMP0135 NEW)
include(FetchContent)

if (NOT JEVITERM_DETERMINISTIC)
    set(ITERM_PROTOBUF_URL https://github.com/gnachman/iTerm2/raw/master/proto/api.proto)
    set(JSON_HPP_URL https://github.com/nlohmann/json/raw/develop/single_include/nlohmann/json.hpp)
else()
    set(ITERM_PROTOBUF_URL https://github.com/gnachman/iTerm2/raw/v3.5.11/proto/api.proto)
    set(JSON_HPP_URL https://github.com/nlohmann/json/raw/v3.11.3/single_include/nlohmann/json.hpp)
endif()

if (NOT JEVITERM_HOMEBREW_DEPS)
    option(ABSL_PROPAGATE_CXX_STD ON)
    option(ABSL_ENABLE_INSTALL OFF)
    add_subdirectory(abseil-cpp)

    option(protobuf_INSTALL OFF)
    option(protobuf_BUILD_TESTS OFF)
    option(protobuf_BUILD_SHARED_LIBS OFF)
    option(protobuf_BUILD_LIBPROTOC OFF)
    add_subdirectory(protobuf)
    include(${CMAKE_CURRENT_SOURCE_DIR}/protobuf/cmake/protobuf-generate.cmake)

    FetchContent_Declare(
        nlohmann_json_fetch
        FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
        DOWNLOAD_NO_EXTRACT TRUE
        URL ${JSON_HPP_URL}
    )
    FetchContent_MakeAvailable(nlohmann_json_fetch)
    FetchContent_GetProperties(nlohmann_json_fetch SOURCE_DIR JSON_HPP_SRC_DIR)

    add_custom_command(OUTPUT
        ${JSON_HPP_SRC_DIR}/nlohmann/json.hpp
        COMMAND ${CMAKE_COMMAND} -E make_directory ${JSON_HPP_SRC_DIR}/nlohmann
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${JSON_HPP_SRC_DIR}/json.hpp ${JSON_HPP_SRC_DIR}/nlohmann/json.hpp
        DEPENDS ${JSON_HPP_SRC_DIR}/json.hpp
    )

    add_library(nlohmann_json INTERFACE ${JSON_HPP_SRC_DIR}/nlohmann/json.hpp)
    target_include_directories(nlohmann_json INTERFACE ${JSON_HPP_SRC_DIR})

    FetchContent_Declare(
        iterm2-protobuf
        FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
        DOWNLOAD_NO_EXTRACT TRUE
        URL ${ITERM_PROTOBUF_URL}
    )
    FetchContent_MakeAvailable(iterm2-protobuf)
    FetchContent_GetProperties(iterm2-protobuf SOURCE_DIR ITERM2_PROTOBUF_SRC_DIR)
    set(ITERM2_PROTOBUF_DL_PATH ${ITERM2_PROTOBUF_SRC_DIR}/api.proto)

else()

    find_package(protobuf CONFIG REQUIRED)
    find_package(nlohmann_json REQUIRED GLOBAL)

endif()

add_custom_command(OUTPUT
    ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${ITERM2_PROTOBUF_DL_PATH} ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto
    DEPENDS ${ITERM2_PROTOBUF_DL_PATH}
)

add_custom_command(OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/iterm-api-proto-dir
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/iterm-api-proto-dir
)

add_library(iterm-api-proto OBJECT ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto)
target_link_libraries(iterm-api-proto PUBLIC protobuf::libprotobuf-lite)
target_include_directories(iterm-api-proto PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/iterm-api-proto-dir)
set_target_properties(iterm-api-proto PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
protobuf_generate(
    TARGET iterm-api-proto
    IMPORT_DIRS ${ITERM2_PROTOBUF_SRC_DIR}
    PLUGIN_OPTIONS "lite"
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/iterm-api-proto-dir
    DEPENDENCIES ${CMAKE_CURRENT_BINARY_DIR}/iterm-api-proto-dir)
