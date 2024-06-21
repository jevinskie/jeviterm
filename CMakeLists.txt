cmake_minimum_required(VERSION 3.22)

project(jeviterm
   LANGUAGES CXX OBJCXX
   VERSION 0.1.5
   DESCRIPTION "C++/Objective-C++ library with a C API to interact with iTerm2 using protobufs and WebSockets"
   HOMEPAGE_URL "https://github.com/jevinskie/jeviterm"
)

set(PRE_CONFIGURE_FILE "include/jeviterm.h.in")
set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/include/jeviterm.h")
set(GIT_FAIL_IF_NONZERO_EXIT OFF)
include(cmake/git_watcher.cmake)

# homebrew llvm toolchain hack
set(CMAKE_XCODE_ATTRIBUTE_COMPILER_INDEX_STORE_ENABLE NO)

option(JEVITERM_FORCE_COLORED_OUTPUT "Always produce ANSI-colored output (GNU/Clang only)." ON)

if (DEFINED ENV{HOMEBREW_PREFIX})
   set(JEVITERM_HOMEBREW_DEPS_DEFAULT ON)
else()
   set(JEVITERM_HOMEBREW_DEPS_DEFAULT OFF)
endif()

option(JEVITERM_HOMEBREW_DEPS "Use homebrew for dependencies." ${JEVITERM_HOMEBREW_DEPS_DEFAULT})

if (JEVITERM_HOMEBREW_DEPS)
   set(JEVITERM_DETERMINISTIC_DEFAULT ON)
else()
   set(JEVITERM_DETERMINISTIC_DEFAULT OFF)
endif()

option(JEVITERM_DETERMINISTIC "Use versioned dependencies instead of latest git HEAD." ${JEVITERM_DETERMINISTIC_DEFAULT})

if (JEVITERM_FORCE_COLORED_OUTPUT)
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
       add_compile_options(-fdiagnostics-color=always)
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang")
       add_compile_options(-fcolor-diagnostics)
    endif ()
endif ()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

# add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
# add_link_options(-fsanitize=address)

add_subdirectory(3rdparty)
add_subdirectory(lib)
add_subdirectory(tools)

