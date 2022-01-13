add_executable(jevitermctl jevitermctl.mm)

target_link_libraries(jevitermctl jeviterm)

target_compile_options(jevitermctl PRIVATE -Oz)

install(TARGETS jevitermctl)
