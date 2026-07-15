if(NOT DEFINED TRACETEST OR NOT DEFINED TRACE_GENERATOR OR NOT DEFINED TEST_DIR)
  message(FATAL_ERROR "TRACETEST, TRACE_GENERATOR, and TEST_DIR are required")
endif()

set(success_trace "${TEST_DIR}/cli-success.frames")
set(failure_trace "${TEST_DIR}/cli-failure.frames")
set(unknown_trace "${TEST_DIR}/cli-unknown-machine.frames")
set(memory_trace "${TEST_DIR}/cli-memory.frames")
execute_process(
  COMMAND "${TRACE_GENERATOR}" "${success_trace}" "${failure_trace}" "${unknown_trace}" "${memory_trace}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "trace generator returned ${result}\n${output}\n${error}")
endif()

set(success_report "${TEST_DIR}/cli-success.json")
execute_process(
  COMMAND "${TRACETEST}" -x -J "${success_report}" "${success_trace}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "strict success returned ${result}, expected 0\n${output}\n${error}")
endif()
file(READ "${success_report}" contents)
if(NOT contents MATCHES "\"machine\":4")
  message(FATAL_ERROR "success report has the wrong machine: ${contents}")
endif()
if(NOT contents MATCHES "\"result\":\"success\"")
  message(FATAL_ERROR "success report has the wrong result: ${contents}")
endif()
if(NOT contents MATCHES "\"success\":1")
  message(FATAL_ERROR "success report has the wrong summary: ${contents}")
endif()

set(memory_report "${TEST_DIR}/cli-memory.json")
execute_process(
  COMMAND "${TRACETEST}" -x -J "${memory_report}" "${memory_trace}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "big-endian memory trace returned ${result}, expected 0\n${output}\n${error}")
endif()
file(READ "${memory_report}" contents)
if(NOT contents MATCHES "\"result\":\"success\"")
  message(FATAL_ERROR "big-endian memory report has the wrong result: ${contents}")
endif()

set(skip_report "${TEST_DIR}/cli-skip.json")
execute_process(
  COMMAND "${TRACETEST}" -x -s nop -J "${skip_report}" "${failure_trace}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "strict skip returned ${result}, expected 0\n${output}\n${error}")
endif()
file(READ "${skip_report}" contents)
if(NOT contents MATCHES "\"result\":\"skipped\"")
  message(FATAL_ERROR "skip report has the wrong result: ${contents}")
endif()
if(NOT contents MATCHES "\"skipped\":1")
  message(FATAL_ERROR "skip report has the wrong summary: ${contents}")
endif()

set(failure_report "${TEST_DIR}/cli-failure.json")
execute_process(
  COMMAND "${TRACETEST}" -x -J "${failure_report}" "${failure_trace}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 1)
  message(FATAL_ERROR "strict semantic failure returned ${result}, expected 1\n${output}\n${error}")
endif()
file(READ "${failure_report}" contents)
if(NOT contents MATCHES "\"result\":\"post_state_mismatch\"")
  message(FATAL_ERROR "failure report has the wrong result: ${contents}")
endif()
if(NOT contents MATCHES "\"post_state_mismatch\":1")
  message(FATAL_ERROR "failure report has the wrong summary: ${contents}")
endif()
if(NOT contents MATCHES "\"register_differences\":\\[\\{")
  message(FATAL_ERROR "failure report is missing register differences: ${contents}")
endif()

execute_process(
  COMMAND "${TRACETEST}" "${failure_trace}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "legacy semantic failure returned ${result}, expected 0\n${output}\n${error}")
endif()

set(input_report "${TEST_DIR}/cli-input-error.json")
execute_process(
  COMMAND "${TRACETEST}" -J "${input_report}" -x does-not-exist.frames
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 2)
  message(FATAL_ERROR "strict input error returned ${result}, expected 2\n${output}\n${error}")
endif()
file(READ "${input_report}" contents)
if(NOT contents MATCHES "\"schema_version\":1")
  message(FATAL_ERROR "input error report is missing its schema version: ${contents}")
endif()
if(NOT contents MATCHES "\"kind\":\"input_or_configuration\"")
  message(FATAL_ERROR "input error report has the wrong error kind: ${contents}")
endif()
if(NOT contents MATCHES "\"unknown\":0")
  message(FATAL_ERROR "input error report is missing its complete summary: ${contents}")
endif()

set(unknown_report "${TEST_DIR}/cli-unknown-machine.json")
execute_process(
  COMMAND "${TRACETEST}" -x -J "${unknown_report}" "${unknown_trace}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)
if(NOT result EQUAL 2)
  message(FATAL_ERROR "unknown M68K machine returned ${result}, expected 2\n${output}\n${error}")
endif()
file(READ "${unknown_report}" contents)
if(NOT contents MATCHES "\"kind\":\"input_or_configuration\"")
  message(FATAL_ERROR "unknown-machine report has the wrong error kind: ${contents}")
endif()

file(REMOVE
  "${success_trace}"
  "${failure_trace}"
  "${unknown_trace}"
  "${memory_trace}"
  "${success_report}"
  "${memory_report}"
  "${skip_report}"
  "${failure_report}"
  "${input_report}"
  "${unknown_report}")
