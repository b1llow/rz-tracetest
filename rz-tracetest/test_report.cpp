// SPDX-FileCopyrightText: 2026 Aya contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include "report.h"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <rz_util/rz_json.h>
#include <vector>

static std::string ReadFile(const char *path) {
	std::ifstream input(path);
	return std::string(std::istreambuf_iterator<char>(input),
		std::istreambuf_iterator<char>());
}

static RzJson *ParseJson(std::string &json, std::vector<char> &storage) {
	storage.assign(json.begin(), json.end());
	storage.push_back('\0');
	return rz_json_parse(storage.data());
}

int main() {
	const char *path = "rz-tracetest-report-test.json";
	TraceReportInfo trace = {
		.trace_version = 3,
		.architecture = frame_arch_m68k,
		.machine = frame_mach_m68020,
		.frame_count = 1,
	};
	FrameReport frame;
	frame.index = 7;
	frame.address = 0x1000;
	frame.has_address = true;
	frame.bytes = "4e71";
	frame.disassembly = "nop\nquoted \"value\"";
	frame.result = FrameCheckResult::PostStateMismatch;
	frame.instruction_id = 42;
	frame.register_differences.push_back({
		.name = "d0",
		.expected = "0x1",
		.actual = "0x2",
	});
	frame.memory_differences.push_back({
		.name = "memory",
		.address = 0x2000,
		.has_address = true,
		.expected = "00",
		.actual = "ff",
	});
	std::array<uint64_t, FRAME_CHECK_RESULT_COUNT> summary = {};
	summary[static_cast<size_t>(FrameCheckResult::PostStateMismatch)] = 1;
	WriteJsonReport(path, trace, { frame }, summary, 1, false);
	std::string json = ReadFile(path);
	assert(json.find("\"schema_version\":1") != std::string::npos);
	assert(json.find("\"machine\":4") != std::string::npos);
	assert(json.find("\"index\":7") != std::string::npos);
	assert(json.find("\"bytes\":\"4e71\"") != std::string::npos);
	assert(json.find("nop\\nquoted \\\"value\\\"") != std::string::npos);
	assert(json.find("\"result\":\"post_state_mismatch\"") != std::string::npos);
	assert(json.find("\"instruction_id\":42") != std::string::npos);
	assert(json.find("\"register_differences\":[{") != std::string::npos);
	assert(json.find("\"memory_differences\":[{") != std::string::npos);
	std::vector<char> storage;
	RzJson *parsed = ParseJson(json, storage);
	assert(parsed && parsed->type == RZ_JSON_OBJECT);
	const RzJson *frames = rz_json_get(parsed, "frames");
	assert(frames && frames->type == RZ_JSON_ARRAY && frames->children.count == 1);
	const RzJson *summary_json = rz_json_get(parsed, "summary");
	assert(summary_json && summary_json->type == RZ_JSON_OBJECT);
	assert(rz_json_get(summary_json, "post_state_mismatch")->num.u_value == 1);
	rz_json_free(parsed);

	WriteJsonErrorReport(path, "bad \"trace\"");
	json = ReadFile(path);
	assert(json.find("\"kind\":\"input_or_configuration\"") != std::string::npos);
	assert(json.find("bad \\\"trace\\\"") != std::string::npos);
	parsed = ParseJson(json, storage);
	assert(parsed && rz_json_get(parsed, "error"));
	summary_json = rz_json_get(parsed, "summary");
	assert(summary_json && rz_json_get(summary_json, "unknown"));
	rz_json_free(parsed);

	std::string schema = ReadFile(REPORT_SCHEMA_PATH);
	parsed = ParseJson(schema, storage);
	assert(parsed && parsed->type == RZ_JSON_OBJECT);
	const RzJson *definitions = rz_json_get(parsed, "$defs");
	assert(definitions && rz_json_get(definitions, "frame"));
	assert(rz_json_get(definitions, "difference"));
	assert(rz_json_get(definitions, "summary"));
	assert(rz_json_get(definitions, "error"));
	const RzJson *variants = rz_json_get(parsed, "oneOf");
	assert(variants && variants->type == RZ_JSON_ARRAY && variants->children.count == 2);
	rz_json_free(parsed);
	std::remove(path);
	return 0;
}
