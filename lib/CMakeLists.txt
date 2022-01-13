find_library(FOUNDATION Foundation)
if (NOT FOUNDATION)
    message(FATAL_ERROR "Foundation not found")
endif()


add_library(jeviterm jeviterm.mm)
target_include_directories(jeviterm PUBLIC ../include)
target_link_libraries(jeviterm PUBLIC ${FOUNDATION})