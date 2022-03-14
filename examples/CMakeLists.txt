# cmake version to be used
cmake_minimum_required(VERSION 3.5)

if (BUILD_EXAMPLES)
    add_executable(kp-consumer-example kp-consumer-example.cpp)
    target_link_libraries(kp-consumer-example PUBLIC nac-abe)

    add_executable(kp-producer-example kp-producer-example.cpp)
    target_link_libraries(kp-producer-example PUBLIC nac-abe)

    add_executable(kp-aa-example kp-aa-example.cpp)
    target_link_libraries(kp-aa-example PUBLIC nac-abe)
endif (BUILD_EXAMPLES)

