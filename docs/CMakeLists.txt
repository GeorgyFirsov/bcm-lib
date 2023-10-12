#
# Configuration flags
#
if (BCMLIB_BUILD_PRETTY_DOCS)
    set(BCMLIB_DOXYGEN_HAVE_DOT         YES)
else (BCMLIB_BUILD_PRETTY_DOCS)
    set(BCMLIB_DOXYGEN_HAVE_DOT         NO)
endif (BCMLIB_BUILD_PRETTY_DOCS)

#
# Setup paths
#
set(BCMLIB_DOCS_VERSION                 ${CMAKE_PROJECT_VERSION})
set(BCMLIB_DOCS_ROOT                    ${BCMLIB_ROOT}/docs)
set(BCMLIB_DOCS_DOXYGEN_AWESOME_ROOT    ${BCMLIB_DOCS_ROOT}/doxygen-awesome-css)
set(BCMLIB_DOCS_DOXYGEN_IN              ${BCMLIB_DOCS_ROOT}/Doxyfile.in)
set(BCMLIB_DOCS_DOXYGEN_OUT             ${BCMLIB_DOCS_ROOT}/Doxyfile)

#
# And here we go...
#
message("[${PROJECT_NAME}]: Configuring doxygen...")

configure_file(${BCMLIB_DOCS_DOXYGEN_IN} 
               ${BCMLIB_DOCS_DOXYGEN_OUT} 
               @ONLY)

#
# In case of GitHub docs we only need a configuration file to be 
# generated, so we quit here in this case
#
if (BCMLIB_BUILD_GITHUB_DOCS)
    message(NOTICE "[${PROJECT_NAME}]: Doxyfile is generated, but BCMLIB_BUILD_GITHUB_DOCS is set, nothing else will be performed")
    message(NOTICE "[${PROJECT_NAME}]: Doxyfile is located here: '${BCMLIB_DOCS_DOXYGEN_OUT}'")
    return()
endif (BCMLIB_BUILD_GITHUB_DOCS)

#
# Otherwise we need to find Doxygen
#
find_package(Doxygen)

#
# Check if we have Doxygen installed
#
if (NOT DOXYGEN_FOUND)
    message(WARNING "[${PROJECT_NAME}]: Doxygen need to be installed to generate the doxygen documentation")
    return()
endif() 

#
# Custom target for building documentation
#
add_custom_target(bcm-lib-docs ALL
    COMMAND ${DOXYGEN_EXECUTABLE} ${BCMLIB_DOCS_DOXYGEN_OUT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating documentation with Doxygen"
    VERBATIM)