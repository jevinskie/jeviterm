find_library(FOUNDATION Foundation)
if (NOT FOUNDATION)
    message(FATAL_ERROR "Foundation not found")
endif()

include(GNUInstallDirs)

find_package(Protobuf REQUIRED)

add_library(jeviterm SHARED jeviterm.mm ${CMAKE_CURRENT_BINARY_DIR}/../include/jeviterm.h iterm-api.pb.cpp iterm-api.pb.h)

target_include_directories(jeviterm PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/../include)
target_include_directories(jeviterm PRIVATE ${Protobuf_INCLUDE_DIRS})

target_link_libraries(jeviterm PRIVATE ${FOUNDATION} ${Protobuf_LIBRARIES})

target_compile_options(jeviterm PRIVATE -Oz -fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections)
target_link_options(jeviterm PRIVATE -Wl,-dead_strip)

# womp, womp -fvirtual-function-elimination crashes jumping to nullptr
target_compile_options(jeviterm PRIVATE -flto=full -fwhole-program-vtables)
target_link_options(jeviterm PRIVATE -Oz -flto=full)

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
