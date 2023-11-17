#
# Find googletest library
#
find_package(GTest CONFIG REQUIRED)

#
# Directories
#
set(BCMLIB_TESTS_ROOT				            ${BCMLIB_ROOT}/tests)
set(BCMLIB_TESTS_INCLUDE                        ${BCMLIB_TESTS_ROOT}/include)
set(BCMLIB_TESTS_CASES                          ${BCMLIB_TESTS_ROOT}/cases)
set(BCMLIB_TESTS_COVERAGE                       ${BCMLIB_TESTS_ROOT}/coverage)

set(BCMLIB_TESTS_INCLUDE_DIRECTORIES	        ${BCMLIB_INCLUDE_DIRECTORIES}
                                                ${BCMLIB_TESTS_INCLUDE}
                                                ${bc-lib_SOURCE_DIR}/include
                                                ${gtest_SOURCE_DIR}/include 
                                                ${gtest_SOURCE_DIR})

#
# Sources and headers
#
set(BCMLIB_SOURCE_FILES                         ${BCMLIB_TESTS_CASES}/cmc_kuznyechik.cpp
                                                ${BCMLIB_TESTS_CASES}/heh_kuznyechik.cpp
                                                ${BCMLIB_TESTS_CASES}/xts_kuznyechik.cpp
                                                ${BCMLIB_TESTS_CASES}/cmac_kuznyechik.cpp
                                                ${BCMLIB_TESTS_CASES}/dec_kuznyechik.cpp)

set(BCMLIB_HEADER_FILES                         ${BCMLIB_TESTS_INCLUDE}/test_data.hpp
                                                ${BCMLIB_TESTS_INCLUDE}/test_common.hpp
                                                ${BCMLIB_TESTS_INCLUDE}/test_utils.hpp)

set(BCMLIB_SOURCES                              ${BCMLIB_SOURCE_FILES}
                                                ${BCMLIB_HEADER_FILES})

#
# Test executable
#
add_executable(bcm-lib-test                     ${BCMLIB_SOURCES})

#
# Include directories
#
target_include_directories(bcm-lib-test PRIVATE ${BCMLIB_TESTS_INCLUDE_DIRECTORIES})

#
# Link with bcm-lib and Google tests
#
target_link_libraries(bcm-lib-test PRIVATE      bcm-lib)
target_link_libraries(bcm-lib-test PRIVATE      GTest::gtest)
target_link_libraries(bcm-lib-test PRIVATE      GTest::gtest_main)

#
# Add target as test
#
add_test(NAME bcm-lib-test 
         COMMAND bcm-lib-test)

#
# Create code coverage reporting script
#
string(REPLACE "/" "\\" BCMLIB_COV_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

configure_file(${BCMLIB_TESTS_COVERAGE}/coverage.cmd.in
               ${CMAKE_BINARY_DIR}/coverage.cmd
               @ONLY)