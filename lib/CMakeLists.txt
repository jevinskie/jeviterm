find_library(FOUNDATION Foundation)
if (NOT FOUNDATION)
    message(FATAL_ERROR "Foundation not found")
endif()

find_package(Protobuf REQUIRED)

add_library(jeviterm jeviterm.mm ../include/jeviterm.h iterm-api.pb.cpp iterm-api.pb.h)
target_include_directories(jeviterm PUBLIC ../include)
target_include_directories(jeviterm PRIVATE ${Protobuf_INCLUDE_DIRS})
target_link_libraries(jeviterm PUBLIC ${FOUNDATION} ${Protobuf_LIBRARIES})
set_target_properties(jeviterm PROPERTIES
    CXX_STANDARD 17
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON)
