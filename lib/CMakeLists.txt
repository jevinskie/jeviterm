include(GNUInstallDirs)

find_package(Boost CONFIG REQUIRED headers)
set_target_properties(Boost::headers PROPERTIES IMPORTED_GLOBAL ON)

add_library(jeviterm SHARED jeviterm.mm ${CMAKE_CURRENT_BINARY_DIR}/../include/jeviterm.h)

target_include_directories(jeviterm PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/../include ${CMAKE_CURRENT_BINARY_DIR} ${JEVITERM_ADDITIONAL_INC_DIRS})
target_include_directories(jeviterm PRIVATE ${Protobuf_INCLUDE_DIRS})

target_link_libraries(jeviterm PRIVATE iterm-api-proto Boost::headers nlohmann_json "-framework Foundation" ${Protobuf_LIBRARIES})

target_compile_options(jeviterm PRIVATE -Oz -fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections)
target_link_options(jeviterm PRIVATE -Wl,-dead_strip)
target_link_options(jeviterm PRIVATE -Wl,-compatibility_version,0.1.0 -Wl,-current_version,${PROJECT_VERSION})

# womp, womp -fvirtual-function-elimination crashes jumping to nullptr
# target_compile_options(jeviterm PRIVATE -flto=full -fwhole-program-vtables)
# target_link_options(jeviterm PRIVATE -Oz -flto=full)

set_target_properties(jeviterm PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    PUBLIC_HEADER ${CMAKE_CURRENT_BINARY_DIR}/../include/jeviterm.h
)

configure_file(jeviterm.pc.in jeviterm.pc @ONLY) 

install(TARGETS jeviterm)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/jeviterm.pc DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig)
