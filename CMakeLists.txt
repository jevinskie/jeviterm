cmake_minimum_required(VERSION 3.22)

project(jeviterm C CXX OBJCXX)

set(CMAKE_XCODE_ATTRIBUTE_COMPILER_INDEX_STORE_ENABLE NO)

option(FORCE_COLORED_OUTPUT "Always produce ANSI-colored output (GNU/Clang only)." ON)

if (${FORCE_COLORED_OUTPUT})
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
       add_compile_options(-fdiagnostics-color=always)
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang")
       add_compile_options(-fcolor-diagnostics)
    endif ()
endif ()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS YES)

# add_compile_options(-fsanitize=address -O0 -g)
# add_link_options(-fsanitize=address)

add_subdirectory(lib)
add_subdirectory(tools)

