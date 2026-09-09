add_executable(sleipnir_tests unit_tests.cpp)
target_link_libraries(sleipnir_tests PRIVATE sleipnir vendor_headers)

add_test(NAME unit_tests COMMAND sleipnir_tests)

# copy data/ next to the test binary so CveDb::load("data/...") works
add_custom_command(TARGET sleipnir_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/data $<TARGET_FILE_DIR:sleipnir_tests>/data)
