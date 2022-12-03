include(GNUInstallDirs)

# find_package(Protobuf REQUIRED)
include(${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/protobuf/cmake/protobuf-generate.cmake)

find_package(Boost CONFIG REQUIRED headers)
set_target_properties(Boost::headers PROPERTIES IMPORTED_GLOBAL ON)

cmake_policy(SET CMP0135 NEW)
include(FetchContent)

FetchContent_Declare(
    iterm2-protobuf
    FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
    DOWNLOAD_NO_EXTRACT TRUE
    URL https://raw.githubusercontent.com/gnachman/iTerm2/master/proto/api.proto
)
FetchContent_MakeAvailable(iterm2-protobuf)
FetchContent_GetProperties(iterm2-protobuf SOURCE_DIR ITERM2_PROTOBUF_SRC_DIR)

FetchContent_Declare(
    json-hpp
    FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
    DOWNLOAD_NO_EXTRACT TRUE
    URL https://github.com/nlohmann/json/raw/develop/single_include/nlohmann/json.hpp
)
FetchContent_MakeAvailable(json-hpp)
FetchContent_GetProperties(json-hpp SOURCE_DIR JSON_HPP_SRC_DIR)


add_custom_command(OUTPUT
    ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto
    COMMAND ${CMAKE_COMMAND} -E copy ${ITERM2_PROTOBUF_SRC_DIR}/api.proto ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto
    DEPENDS ${ITERM2_PROTOBUF_SRC_DIR}/api.proto
)

add_custom_command(OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/iterm-api.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/iterm-api.pb.h
    COMMAND $<TARGET_FILE:protobuf::protoc> --cpp_out=code_size:${CMAKE_CURRENT_BINARY_DIR} --proto_path ${protobuf_SOURCE_DIR}/src --proto_path ${ITERM2_PROTOBUF_SRC_DIR} ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto
    DEPENDS ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto
)

add_library(iterm-api-proto OBJECT ${ITERM2_PROTOBUF_SRC_DIR}/iterm-api.proto)
target_link_libraries(iterm-api-proto PUBLIC protobuf::libprotobuf)
protobuf_generate(
    TARGET iterm-api-proto
    IMPORT_DIRS ${ITERM2_PROTOBUF_SRC_DIR}
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR})


add_library(jeviterm SHARED jeviterm.mm ${CMAKE_CURRENT_BINARY_DIR}/../include/jeviterm.h)

target_include_directories(jeviterm PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/../include ${CMAKE_CURRENT_BINARY_DIR} ${JSON_HPP_SRC_DIR})
target_include_directories(jeviterm PRIVATE ${Protobuf_INCLUDE_DIRS})

target_link_libraries(jeviterm PRIVATE iterm-api-proto Boost::headers "-framework Foundation" ${Protobuf_LIBRARIES})

# target_compile_options(jeviterm PRIVATE -Oz -fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections)
# target_link_options(jeviterm PRIVATE -Wl,-dead_strip)

# womp, womp -fvirtual-function-elimination crashes jumping to nullptr
# target_compile_options(jeviterm PRIVATE -flto=full -fwhole-program-vtables)
# target_link_options(jeviterm PRIVATE -Oz -flto=full)

set(JEVITERM_INSTALL_NAME_DIR ${CMAKE_INSTALL_FULL_LIBDIR})
if (DEFINED ENV{HOMEBREW_PREFIX})
    set(JEVITERM_INSTALL_NAME_DIR $ENV{HOMEBREW_PREFIX}/opt/jeviterm/lib)
endif()

set_target_properties(jeviterm PROPERTIES
    CXX_STANDARD 17
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    INSTALL_NAME_DIR ${JEVITERM_INSTALL_NAME_DIR}
    PUBLIC_HEADER ${CMAKE_CURRENT_BINARY_DIR}/../include/jeviterm.h
)

configure_file(jeviterm.pc.in jeviterm.pc @ONLY) 

install(TARGETS jeviterm)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/jeviterm.pc DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig)
