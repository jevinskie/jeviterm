include(GNUInstallDirs)

find_package(Boost CONFIG REQUIRED headers)
set_target_properties(Boost::headers PROPERTIES IMPORTED_GLOBAL ON)

add_library(jeviterm SHARED jeviterm.mm ${CMAKE_CURRENT_BINARY_DIR}/../include/jeviterm.h)

if (NOT JEVITERM_HOMEBREW_DEPS)
    set(JEVITERM_ADDITIONAL_INC_DIRS ${JSON_HPP_SRC_DIR})
else()
    set(JEVITERM_ADDITIONAL_LIBS nlohmann_json::nlohmann_json)
endif()

target_include_directories(jeviterm PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/../include ${CMAKE_CURRENT_BINARY_DIR} ${JEVITERM_ADDITIONAL_INC_DIRS})
target_include_directories(jeviterm PRIVATE ${Protobuf_INCLUDE_DIRS})

target_link_libraries(jeviterm PRIVATE iterm-api-proto Boost::headers "-framework Foundation" ${Protobuf_LIBRARIES} nlohmann_json)

target_compile_options(jeviterm PRIVATE -Oz -fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections)
target_link_options(jeviterm PRIVATE -Wl,-dead_strip)

# womp, womp -fvirtual-function-elimination crashes jumping to nullptr
# target_compile_options(jeviterm PRIVATE -flto=full -fwhole-program-vtables)
# target_link_options(jeviterm PRIVATE -Oz -flto=full)

set(JEVITERM_INSTALL_NAME_DIR ${CMAKE_INSTALL_FULL_LIBDIR})
if (DEFINED ENV{HOMEBREW_PREFIX})
    set(JEVITERM_INSTALL_NAME_DIR $ENV{HOMEBREW_PREFIX}/opt/jeviterm/lib)
endif()

set_target_properties(jeviterm PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    INSTALL_NAME_DIR ${JEVITERM_INSTALL_NAME_DIR}
    PUBLIC_HEADER ${CMAKE_CURRENT_BINARY_DIR}/../include/jeviterm.h
)

configure_file(jeviterm.pc.in jeviterm.pc @ONLY) 

install(TARGETS jeviterm)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/jeviterm.pc DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig)
