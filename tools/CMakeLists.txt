add_executable(jevitermctl jevitermctl.mm)

target_link_libraries(jevitermctl jeviterm)

target_compile_options(jevitermctl PRIVATE -Oz)

target_link_options(jevitermctl PRIVATE -Wl,-rpath,@loader_path/../lib)

# message(FATAL_ERROR "JEVITERMCTL_RPATH: ${JEVITERMCTL_RPATH}")

set_target_properties(jevitermctl PROPERTIES
    CXX_STANDARD 23
    CXX_EXTENSIONS ON
    CXX_STANDARD_REQUIRED ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

install(TARGETS jevitermctl)
