add_executable(sleipnir-cli main.cpp)
target_compile_definitions(sleipnir-cli PRIVATE SLEIPNIR_VERSION="${PROJECT_VERSION}")
target_link_libraries(sleipnir-cli PRIVATE sleipnir vendor_headers)
set_target_properties(sleipnir-cli PROPERTIES OUTPUT_NAME sleipnir)
