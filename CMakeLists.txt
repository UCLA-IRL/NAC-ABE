# cmake version to be used
cmake_minimum_required(VERSION 3.5)

# project name
project(nac-abe
        VERSION 0.1
        DESCRIPTION "NDN Name-based access control - attribute based encryption library")

# flags
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
if (HAVE_TESTS)
    add_compile_definitions(HAVE_TESTS)
endif(HAVE_TESTS)

# dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(NDN_CXX REQUIRED libndn-cxx>=0.8.1)
find_package(OpenSSL REQUIRED)

find_library(openabe NAMES openabe REQUIRED)

# files
file(GLOB_RECURSE NAC_ABE_LIB_SOURCE_FILES "src/*.cpp" "src/**/*.cpp")

# include
include_directories(${NDN_CXX_INCLUDE_DIRS})
include_directories(src)
include_directories(build/src)

add_compile_definitions(SYSCONFDIR="${CMAKE_INSTALL_PREFIX}/etc")
add_compile_definitions(NAC_ABE_CMAKE_BUILD)

# link
link_directories(${NDN_CXX_LIBRARY_DIRS})

# target
add_library(nac-abe SHARED ${NAC_ABE_LIB_SOURCE_FILES})
target_compile_options(nac-abe PUBLIC ${NDN_CXX_CFLAGS})
target_link_libraries(nac-abe PUBLIC ${NDN_CXX_LIBRARIES} openabe)

add_subdirectory(tests)
add_subdirectory(examples)

# install
set(PKG_CONFIG_REQUIRES
        "libndn-cxx >= ${NDN_CXX_VERSION}"
        )
set(PKG_CONFIG_LIBS
        "-L\${libdir} -l${PROJECT_NAME}"
        )
set(PKG_CONFIG_CFLAGS
        "-I\${includedir} -DNAC_ABE_CMAKE_BUILD"
        )
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake-pkgconfig.pc.in"
        "${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.pc")

include(GNUInstallDirs)
install(TARGETS nac-abe
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nac-abe
        )
install(DIRECTORY src/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nac-abe
        FILES_MATCHING PATTERN "*.h*")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.pc"
        DESTINATION lib/pkgconfig)

