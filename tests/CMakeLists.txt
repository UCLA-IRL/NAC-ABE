# cmake version to be used
cmake_minimum_required(VERSION 3.5)

if (HAVE_TESTS)
    enable_testing()

    find_package(Boost REQUIRED COMPONENTS unit_test_framework)
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories(${Boost_LIBRARY_DIRS})
    # set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
    # set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

    file(GLOB_RECURSE test_source "*.cpp" "unit-tests/*.cpp")
    add_executable(unit-tests ${test_source})
    target_include_directories(unit-tests PUBLIC .)
    target_link_libraries(unit-tests PUBLIC nac-abe)
    target_link_libraries(unit-tests PUBLIC ${Boost_LIBRARIES})

    add_test(NAME unit-tests COMMAND unit-tests -l test_suite -x)

    if (BUILD_EXAMPLES)
        add_test(NAME example-tests COMMAND bash ${CMAKE_SOURCE_DIR}/examples/run-examples.sh ${CMAKE_BINARY_DIR})
    endif (BUILD_EXAMPLES)
endif (HAVE_TESTS)
