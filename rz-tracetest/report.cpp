// SPDX-FileCopyrightText: 2026 Aya contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include "report.h"

#include <fstream>
#include <iomanip>
#include <stdexcept>

const char *FrameCheckResultName(FrameCheckResult result) {
	switch (result) {
	case FrameCheckResult::Success:
		return "success";
	case FrameCheckResult::Skipped:
		return "skipped";
	case FrameCheckResult::InvalidOp:
		return "invalid_op";
	case FrameCheckResult::InvalidIL:
		return "invalid_il";
	case FrameCheckResult::VMRuntimeError:
		return "vm_runtime_error";
	case FrameCheckResult::PostStateMismatch:
		return "post_state_mismatch";
	case FrameCheckResult::Unimplemented:
		return "unimplemented";
	case FrameCheckResult::Unknown:
		return "unknown";
	}
	return "unknown";
}

static void WriteJsonString(std::ostream &out, const std::string &value) {
	out << '"';
	for (unsigned char c : value) {
		switch (c) {
		case '"':
			out << "\\\"";
			break;
		case '\\':
			out << "\\\\";
			break;
		case '\b':
			out << "\\b";
			break;
		case '\f':
			out << "\\f";
			break;
		case '\n':
			out << "\\n";
			break;
		case '\r':
			out << "\\r";
			break;
		case '\t':
			out << "\\t";
			break;
		default:
			if (c < 0x20) {
				out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
				    << static_cast<unsigned int>(c) << std::dec << std::setfill(' ');
			} else {
				out << static_cast<char>(c);
			}
			break;
		}
	}
	out << '"';
}

static void WriteDifferences(std::ostream &out,
	const std::vector<FrameValueDifference> &differences) {
	out << '[';
	for (size_t i = 0; i < differences.size(); i++) {
		if (i) {
			out << ',';
		}
		const FrameValueDifference &difference = differences[i];
		out << "{\"name\":";
		WriteJsonString(out, difference.name);
		if (difference.has_address) {
			out << ",\"address\":" << difference.address;
		}
		out << ",\"expected\":";
		WriteJsonString(out, difference.expected);
		out << ",\"actual\":";
		WriteJsonString(out, difference.actual);
		out << '}';
	}
	out << ']';
}

static std::ofstream OpenReport(const std::string &path) {
	std::ofstream out(path, std::ios::out | std::ios::trunc);
	if (!out) {
		throw std::runtime_error("Failed to open JSON report: " + path);
	}
	return out;
}

void WriteJsonReport(const std::string &path, const TraceReportInfo &trace,
	const std::vector<FrameReport> &frames,
	const std::array<uint64_t, FRAME_CHECK_RESULT_COUNT> &summary,
	uint64_t unique_instructions, bool interrupted) {
	std::ofstream out = OpenReport(path);
	out << "{\"schema\":\"rz-tracetest-report-v1\",\"schema_version\":1,";
	out << "\"tool\":\"rz-tracetest\",\"trace\":{";
	out << "\"version\":" << trace.trace_version;
	out << ",\"architecture\":" << trace.architecture;
	out << ",\"machine\":" << trace.machine;
	out << ",\"frame_count\":" << trace.frame_count << "},\"frames\":[";
	for (size_t i = 0; i < frames.size(); i++) {
		if (i) {
			out << ',';
		}
		const FrameReport &frame = frames[i];
		out << "{\"index\":" << frame.index;
		if (frame.has_address) {
			out << ",\"address\":" << frame.address;
		} else {
			out << ",\"address\":null";
		}
		out << ",\"bytes\":";
		WriteJsonString(out, frame.bytes);
		out << ",\"disassembly\":";
		WriteJsonString(out, frame.disassembly);
		out << ",\"result\":";
		WriteJsonString(out, FrameCheckResultName(frame.result));
		out << ",\"instruction_id\":" << frame.instruction_id;
		out << ",\"register_differences\":";
		WriteDifferences(out, frame.register_differences);
		out << ",\"memory_differences\":";
		WriteDifferences(out, frame.memory_differences);
		out << ",\"details\":[";
		for (size_t j = 0; j < frame.details.size(); j++) {
			if (j) {
				out << ',';
			}
			WriteJsonString(out, frame.details[j]);
		}
		out << "]}";
	}
	out << "],\"summary\":{\"processed\":" << frames.size();
	for (size_t i = 0; i < summary.size(); i++) {
		out << ',';
		WriteJsonString(out, FrameCheckResultName(static_cast<FrameCheckResult>(i)));
		out << ':' << summary[i];
	}
	out << ",\"unique_instructions\":" << unique_instructions;
	out << ",\"interrupted\":" << (interrupted ? "true" : "false") << "}}\n";
	if (!out) {
		throw std::runtime_error("Failed to write JSON report: " + path);
	}
}

void WriteJsonErrorReport(const std::string &path, const std::string &message) {
	std::ofstream out = OpenReport(path);
	out << "{\"schema\":\"rz-tracetest-report-v1\",\"schema_version\":1,";
	out << "\"tool\":\"rz-tracetest\",\"error\":{";
	out << "\"kind\":\"input_or_configuration\",\"message\":";
	WriteJsonString(out, message);
	out << "},\"frames\":[],\"summary\":{";
	out << "\"processed\":0,\"success\":0,\"skipped\":0,\"invalid_op\":0,";
	out << "\"invalid_il\":0,\"vm_runtime_error\":0,\"post_state_mismatch\":0,";
	out << "\"unimplemented\":0,\"unknown\":0,\"unique_instructions\":0,";
	out << "\"interrupted\":false}}\n";
	if (!out) {
		throw std::runtime_error("Failed to write JSON error report: " + path);
	}
}
