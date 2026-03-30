if(NOT DEFINED INPUT_FILE OR NOT DEFINED OUTPUT_FILE)
    message(FATAL_ERROR "INPUT_FILE and OUTPUT_FILE are required")
endif()

file(READ "${INPUT_FILE}" HOMEPAGE_HTML_CONTENT)
get_filename_component(OUTPUT_DIR "${OUTPUT_FILE}" DIRECTORY)
file(MAKE_DIRECTORY "${OUTPUT_DIR}")

file(WRITE "${OUTPUT_FILE}" "#pragma once\n\nnamespace generated {\ninline constexpr const char kHomepageHtml[] = R\"qtunnel_html(")
file(APPEND "${OUTPUT_FILE}" "${HOMEPAGE_HTML_CONTENT}")
file(APPEND "${OUTPUT_FILE}" ")qtunnel_html\";\n} // namespace generated\n")
