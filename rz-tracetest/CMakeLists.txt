cmake_minimum_required(VERSION 3.12)
project(rz-tracetest)
set(CMAKE_CXX_STANDARD 17)
include(CTest)

find_package(Rizin REQUIRED Core)

option(ENABLE_ASAN "Enable address sanitizer" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (ENABLE_ASAN)
    message("Enabling ASAN")
    add_definitions(-DASAN_ENABLED)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

add_subdirectory(libtrace)

set(SOURCE
	main.cpp
	rzemu.cpp
	rzemu.h
	adapter.h
	adapter.cpp
	dump.h
	dump.cpp
	report.h
	report.cpp)

add_executable(rz-tracetest ${SOURCE})
target_link_libraries(rz-tracetest Rizin::Core trace)
install(TARGETS rz-tracetest)
install(FILES report.schema.json DESTINATION share/rz-tracetest)

if (BUILD_TESTING)
	add_executable(test-adapter adapter.cpp test_adapter.cpp)
	target_link_libraries(test-adapter Rizin::Core trace)
	add_test(NAME adapter COMMAND test-adapter)

	add_executable(test-report report.cpp test_report.cpp)
	target_link_libraries(test-report Rizin::Core trace)
	target_compile_definitions(test-report PRIVATE
		REPORT_SCHEMA_PATH="${CMAKE_CURRENT_SOURCE_DIR}/report.schema.json")
	add_test(NAME report COMMAND test-report)

	add_executable(test-trace test_trace.cpp)
	target_link_libraries(test-trace trace)

	add_test(
		NAME cli-contract
		COMMAND ${CMAKE_COMMAND}
			-DTRACETEST=$<TARGET_FILE:rz-tracetest>
			-DTRACE_GENERATOR=$<TARGET_FILE:test-trace>
			-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}
			-P ${CMAKE_CURRENT_SOURCE_DIR}/test_cli.cmake)
endif()
