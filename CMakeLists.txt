cmake_minimum_required(VERSION 3.5.0)
project(bcm-lib VERSION 1.0.1)

#
# Global config
#
set(CMAKE_CXX_STANDARD                                  17)
set(CMAKE_CXX_STANDARD_REQUIRED                         True)

#
# Options
#
option(BCMLIB_KERNEL_MODE                               "Build bcm-lib for kernel mode too (Windows only)." OFF)
option(BCMLIB_GENERATE_DOCS                             "Generate documentation for bcm-lib." OFF)
option(BCMLIB_DOCS_ONLY                                 "Generate documentation only (bcm-lib will not be built." OFF)
option(BCMLIB_GITHUB_DOCS                               "Generate documentation for GitHub." OFF)
option(BCMLIB_PRETTY_DOCS                               "Use graphwiz for diagrams." OFF)
option(BCMLIB_ENABLE_TESTING                            "Enable testing of ciphers, modes of operation and other functions." ON)

#
# Configuration
#
if (WIN32)
    set(BCMLIB_WINDOWS_BUILD                            ON)
else (WIN32)
    set(BCMLIB_WINDOWS_BUILD                            OFF)
endif (WIN32)

if (BCMLIB_GENERATE_DOCS AND BCMLIB_DOCS_ONLY)

    #
    # Building docs only
    #

    set(BCMLIB_BUILD_LIB                                OFF)
    set(BCMLIB_BUILD_TESTS                              OFF)
    set(BCMLIB_BUILD_DOCS                               ON)
    set(BCMLIB_BUILD_GITHUB_DOCS                        ${BCMLIB_GITHUB_DOCS})
    set(BCMLIB_BUILD_PRETTY_DOCS                        ${BCMLIB_PRETTY_DOCS})

    #
    # Just set this to OFF, because no binary is built
    #
    set(BCMLIB_BUILD_KERNEL_LIB                         OFF)

else (BCMLIB_GENERATE_DOCS AND BCMLIB_DOCS_ONLY)

    #
    # Here I assume other flags, but library 
    # will be built always here.
    #

    set(BCMLIB_BUILD_LIB                                ON)
    set(BCMLIB_BUILD_TESTS                              ${BCMLIB_ENABLE_TESTING})
    set(BCMLIB_BUILD_DOCS                               ${BCMLIB_GENERATE_DOCS})
    set(BCMLIB_BUILD_GITHUB_DOCS                        ${BCMLIB_GITHUB_DOCS})
    set(BCMLIB_BUILD_PRETTY_DOCS                        ${BCMLIB_PRETTY_DOCS})

    #
    # Kernel mode library is supporten on Windows only
    #
    if (BCMLIB_WINDOWS_BUILD)

        set(BCMLIB_BUILD_KERNEL_LIB                     ${BCMLIB_KERNEL_MODE})
        
    else (BCMLIB_WINDOWS_BUILD)

        message(STATUS "[${PROJECT_NAME}]: Non-Windows version, BCMLIB_BUILD_KERNEL_LIB will set to OFF.")
        set(BCMLIB_BUILD_KERNEL_LIB                     OFF)

    endif (BCMLIB_WINDOWS_BUILD)

endif (BCMLIB_GENERATE_DOCS AND BCMLIB_DOCS_ONLY)

message("[${PROJECT_NAME}]: BCMLIB_WINDOWS_BUILD     = ${BCMLIB_WINDOWS_BUILD}")
message("[${PROJECT_NAME}]: BCMLIB_BUILD_LIB         = ${BCMLIB_BUILD_LIB}")
message("[${PROJECT_NAME}]: BCMLIB_BUILD_KERNEL_LIB  = ${BCMLIB_BUILD_KERNEL_LIB}")
message("[${PROJECT_NAME}]: BCMLIB_BUILD_TESTS       = ${BCMLIB_BUILD_TESTS}")
message("[${PROJECT_NAME}]: BCMLIB_BUILD_DOCS        = ${BCMLIB_BUILD_DOCS}")
message("[${PROJECT_NAME}]: BCMLIB_BUILD_GITHUB_DOCS = ${BCMLIB_BUILD_GITHUB_DOCS}")
message("[${PROJECT_NAME}]: BCMLIB_BUILD_PRETTY_DOCS = ${BCMLIB_BUILD_PRETTY_DOCS}")

#
# Just sanity check if we are going well
#
if (NOT BCMLIB_BUILD_LIB AND BCMLIB_BUILD_TESTS)
    message(FATAL_ERROR "[${PROJECT_NAME}]: cannot build tests without building bcm-lib itself")
endif (NOT BCMLIB_BUILD_LIB AND BCMLIB_BUILD_TESTS)

#
# Configure dependencies:
# - propagate kernel lib building flag
# - disable documentation generation
# - disable tests
#
include(FetchContent)

option(GALOISLIB_GENERATE_DOCS ""                       OFF)
option(GALOISLIB_KERNEL_MODE ""                         ${BCMLIB_BUILD_KERNEL_LIB})

FetchContent_Declare(
    galois-lib
    GIT_REPOSITORY https://github.com/GeorgyFirsov/galois-lib.git
    GIT_TAG        v1.0.6
)

option(BCLIB_GENERATE_DOCS ""                           OFF)
option(BCLIB_ENABLE_TESTING ""                          OFF)
option(BCLIB_KERNEL_MODE ""                             ${BCMLIB_BUILD_KERNEL_LIB})

FetchContent_Declare(
    bc-lib
    GIT_REPOSITORY https://github.com/GeorgyFirsov/bc-lib.git
    GIT_TAG        v1.1.0
)

option(KDFLIB_GENERATE_DOCS ""                          OFF)
option(KDFLIB_ENABLE_TESTING ""                         OFF)
option(KDFLIB_KERNEL_MODE ""                            ${BCMLIB_BUILD_KERNEL_LIB})

FetchContent_Declare(
    kdf-lib
    GIT_REPOSITORY https://github.com/GeorgyFirsov/kdf-lib.git
    GIT_TAG        f9522bf  # kdf-lib is not released for now
)

FetchContent_MakeAvailable(galois-lib bc-lib kdf-lib)

#
# Set global directories
#
set(BCMLIB_ROOT		                                    ${CMAKE_CURRENT_LIST_DIR})
set(BCMLIB_SOURCES_ROOT								    ${BCMLIB_ROOT}/src)
set(BCMLIB_INCLUDE_ROOT								    ${BCMLIB_ROOT}/include)
set(BCMLIB_INCLUDE_DIRECTORIES						    ${BCMLIB_INCLUDE_ROOT})

#
# Set output directories for all targets
#
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY                      ${CMAKE_BINARY_DIR}/out)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY                      ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY                      ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE              ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE              ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE              ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG                ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG                ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG                ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

#
# Now let's build targets according to the flags set before
#
if (BCMLIB_BUILD_LIB)
    
    #
    # FindWDK module
    #
    list(APPEND CMAKE_MODULE_PATH	                    ${CMAKE_SOURCE_DIR}/third-party/FindWDK/cmake)
    
    #
    # Preprocessor definitions
    #
    add_compile_definitions(UNICODE)

    #
    # Implementation directories
    #
    set(BCMLIB_MODES_SOURCES_DIR						${BCMLIB_SOURCES_ROOT}/modes)
    set(BCMLIB_MODES_INCLUDE_DIR						${BCMLIB_INCLUDE_ROOT}/modes)
    set(BCMLIB_COMMON_INCLUDE_DIR						${BCMLIB_INCLUDE_ROOT}/common)

    set(BCMLIB_INTERNAL_INCLUDE_DIRECTORIES             ${BCMLIB_INCLUDE_DIRECTORIES}
                                                        ${BCMLIB_COMMON_INCLUDE_DIR}
                                                        ${bc-lib_SOURCE_DIR}/include
                                                        ${galois-lib_SOURCE_DIR}/include
                                                        ${kdf-lib_SOURCE_DIR}/include)

    set(BCMLIB_XTS_SOURCES_DIR							${BCMLIB_MODES_SOURCES_DIR}/xts)
    set(BCMLIB_XTS_INCLUDE_DIR							${BCMLIB_MODES_INCLUDE_DIR}/xts)

    set(BCMLIB_CMC_SOURCES_DIR							${BCMLIB_MODES_SOURCES_DIR}/cmc)
    set(BCMLIB_CMC_INCLUDE_DIR							${BCMLIB_MODES_INCLUDE_DIR}/cmc)

    set(BCMLIB_HEH_SOURCES_DIR							${BCMLIB_MODES_SOURCES_DIR}/heh)
    set(BCMLIB_HEH_INCLUDE_DIR							${BCMLIB_MODES_INCLUDE_DIR}/heh)

    set(BCMLIB_CMAC_SOURCES_DIR							${BCMLIB_MODES_SOURCES_DIR}/cmac)
    set(BCMLIB_CMAC_INCLUDE_DIR							${BCMLIB_MODES_INCLUDE_DIR}/cmac)

    set(BCMLIB_DEC_SOURCES_DIR							${BCMLIB_MODES_SOURCES_DIR}/dec)
    set(BCMLIB_DEC_INCLUDE_DIR							${BCMLIB_MODES_INCLUDE_DIR}/dec)

    #
    # Source files
    #
    set(BCMLIB_SOURCE_FILES								${BCMLIB_XTS_SOURCES_DIR}/xts.c
                                                        ${BCMLIB_CMC_SOURCES_DIR}/cmc.c
                                                        ${BCMLIB_HEH_SOURCES_DIR}/heh.c
                                                        ${BCMLIB_CMAC_SOURCES_DIR}/cmac.c
                                                        ${BCMLIB_DEC_SOURCES_DIR}/dec.c)

    set(BCMLIB_HEADER_FILES								${BCMLIB_XTS_INCLUDE_DIR}/xts.h
                                                        ${BCMLIB_CMC_INCLUDE_DIR}/cmc.h
                                                        ${BCMLIB_HEH_INCLUDE_DIR}/heh.h
                                                        ${BCMLIB_CMAC_INCLUDE_DIR}/cmac.h
                                                        ${BCMLIB_DEC_INCLUDE_DIR}/dec.h
                                                        ${BCMLIB_COMMON_INCLUDE_DIR}/utils.h
                                                        ${BCMLIB_INCLUDE_ROOT}/bcmlib.h)

    set(BCMLIB_SOURCES									${BCMLIB_SOURCE_FILES}
                                                        ${BCMLIB_HEADER_FILES})

    #
    # Library itself (may be built for user mode as 
    # well as for kernel mode)
    #
    add_library(bcm-lib									${BCMLIB_SOURCES})

    if (BCMLIB_BUILD_KERNEL_LIB)
        message("[${PROJECT_NAME}]: Building additional target for kernel mode")

        find_package(WDK REQUIRED)
        wdk_add_library(bcm-lib-km						${BCMLIB_SOURCES})
    endif (BCMLIB_BUILD_KERNEL_LIB)


    #
    # Include directories
    #
    target_include_directories(bcm-lib PRIVATE 			${BCMLIB_INTERNAL_INCLUDE_DIRECTORIES})

    if (BCMLIB_BUILD_KERNEL_LIB)
        target_include_directories(bcm-lib-km PRIVATE 	${BCMLIB_INTERNAL_INCLUDE_DIRECTORIES})
    endif (BCMLIB_BUILD_KERNEL_LIB)


    #
    # Link with dependencies
    #
    target_link_libraries(bcm-lib PRIVATE                galois-lib) 
    target_link_libraries(bcm-lib PRIVATE                bc-lib) 
    target_link_libraries(bcm-lib PRIVATE                kdf-lib) 

    if (BCLIB_BUILD_KERNEL_LIB)
        target_link_libraries(bcm-lib-km PRIVATE         galois-lib-km)
        target_link_libraries(bcm-lib-km PRIVATE         bc-lib-km)
        target_link_libraries(bcm-lib-km PRIVATE         kdf-lib-km)
    endif (BCLIB_BUILD_KERNEL_LIB)


    #
    # On non-Windows builds it is necessary to add some intrinsics support
    #
    if (NOT BCMLIB_WINDOWS_BUILD)
        target_compile_options(bcm-lib PRIVATE 			-mpclmul)
        target_compile_options(bcm-lib PRIVATE          -msse4.1)
    endif (NOT BCMLIB_WINDOWS_BUILD)

endif (BCMLIB_BUILD_LIB)

if (BCMLIB_BUILD_TESTS)

    include(CTest)

    #
    # Tests target
    #
    add_subdirectory(tests)

endif (BCMLIB_BUILD_TESTS)

if (BCMLIB_BUILD_DOCS)

    #
    # Docs target
    #
    add_subdirectory(docs)

endif (BCMLIB_BUILD_DOCS)