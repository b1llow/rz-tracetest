// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dump.h"
#include "report.h"
#include "rzemu.h"

#include <array>
#include <cerrno>
#include <regex>
#include <rz_util/rz_set.h>
#include <vector>

static int help(bool verbose) {
	printf("Usage: rz-tracetest [-dbeurmphivnx] [-J report.json] [-c count] [-o offset] [-s regex] <filename>.frames\n");
	if (verbose) {
		printf(" -c [count]    number of frames to check, default: all\n");
		printf(" -d            dump trace as text, but do not run or test anything\n");
		printf(" -b            Interpret trace from a big endian architecture.\n");
		printf(" -e            fail early/stop at the first error\n");
		printf(" -u            fail early/stop at the first unlifted execption\n");
		printf(" -r            fail early/stop at the first runtime error\n");
		printf(" -m            fail early/stop at the first execution mismatch\n");
		printf(" -p            prettify IL outputs\n");
		printf(" -n            no io cache reset. Bytes of all frames will be written once and won't be reset for every frame.\n");
		printf(" -h            show help message\n");
		printf(" -i            do not print unlifted instructions verbosely\n");
		printf(" -J [path]     write a versioned JSON report\n");
		printf(" -o [offset]   index of the first frame to check, default: 0\n");
		printf(" -s [regex]    skip every frame whose disassembly string matches the given regex\n");
		printf(" -v            be more verbose (can be repeated)\n");
		printf(" -x            strict exit codes: 0 success/skip, 1 semantic failure, 2 input/configuration error\n");
	}
	return 1;
}

static ut64 ParseU64Option(const char *option, const std::string &value) {
	errno = 0;
	char *end = nullptr;
	unsigned long long parsed = strtoull(value.c_str(), &end, 0);
	if (value.empty() || value[0] == '-' || errno == ERANGE || !end || *end) {
		throw RizinException("Invalid value for %s: %s", option, value.c_str());
	}
	return static_cast<ut64>(parsed);
}

static int InputError(const std::optional<std::string> &report_path,
	bool strict_exit, const std::string &message) {
	eprintf("rz-tracetest: %s\n", message.c_str());
	if (report_path) {
		try {
			WriteJsonErrorReport(*report_path, message);
		} catch (const std::exception &report_error) {
			eprintf("rz-tracetest: %s\n", report_error.what());
		}
	}
	return strict_exit ? 2 : 1;
}

int main(int argc, const char *argv[]) {
	ut64 count = UT64_MAX;
	ut64 offset = 0;
	bool invalid_op_quiet = false;
	bool dump_only = false;
	bool fail_early = false;
	bool fail_unlifted = false;
	bool fail_runtime = false;
	bool fail_misexec = false;
	bool big_endian = false;
	bool prettify_il = false;
	bool cache_reset = true;
	bool strict_exit = false;
	bool help_requested = false;
	int verbose = 0;
	std::optional<std::string> count_arg;
	std::optional<std::string> offset_arg;
	std::optional<std::string> skip_arg;
	std::optional<std::string> report_path;
	std::optional<std::string> command_line_error;

	RzGetopt opt;
	rz_getopt_init(&opt, argc, (const char **)argv, "hc:o:idbvs:eurmpnJ:x");
	int c;

	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'h':
			help_requested = true;
			break;
		case 'c':
			count_arg = opt.arg;
			break;
		case 'o':
			offset_arg = opt.arg;
			break;
		case 'i':
			invalid_op_quiet = true;
			break;
		case 'b':
			big_endian = true;
			break;
		case 'd':
			dump_only = true;
			break;
		case 'e':
			fail_early = true;
			break;
		case 'u':
			fail_unlifted = true;
			break;
		case 'r':
			fail_runtime = true;
			break;
		case 'm':
			fail_misexec = true;
			break;
		case 'p':
			prettify_il = true;
			break;
		case 'n':
			cache_reset = false;
			break;
		case 's':
			if (skip_arg) {
				command_line_error = "-s can only be specified once (use |)";
			} else {
				skip_arg = opt.arg;
			}
			break;
		case 'v':
			verbose++;
			break;
		case 'J':
			if (report_path) {
				command_line_error = "-J can only be specified once";
			} else {
				report_path = opt.arg;
			}
			break;
		case 'x':
			strict_exit = true;
			break;
		default:
			command_line_error = "invalid command-line option";
			break;
		}
	}
	if (help_requested) {
		help(true);
		return strict_exit ? 0 : 1;
	}
	if (command_line_error) {
		return InputError(report_path, strict_exit, *command_line_error);
	}
	if (opt.ind + 1 != argc) {
		help(false);
		return InputError(report_path, strict_exit, "expected exactly one trace filename");
	}

	try {
		if (count_arg) {
			count = ParseU64Option("-c", *count_arg);
		}
		if (offset_arg) {
			offset = ParseU64Option("-o", *offset_arg);
		}
		if (dump_only && report_path) {
			throw RizinException("-J cannot be combined with -d.");
		}

		std::optional<std::regex> skip_re;
		if (skip_arg) {
			try {
				skip_re.emplace(*skip_arg, std::regex_constants::egrep);
			} catch (const std::regex_error &error) {
				throw RizinException("Invalid skip regex: %s", error.what());
			}
		}
		std::optional<std::function<bool(const std::string &)>> skip_by_disasm;
		if (skip_re) {
			const std::regex &re = *skip_re;
			skip_by_disasm = [&re](const std::string &disasm) {
				return std::regex_match(disasm, re);
			};
		}

		SerializedTrace::TraceContainerReader trace(argv[opt.ind]);
		TraceReportInfo report_info = {
			.trace_version = trace.get_trace_version(),
			.architecture = static_cast<uint64_t>(trace.get_arch()),
			.machine = trace.get_machine(),
			.frame_count = trace.get_num_frames(),
		};
		auto adapter = SelectTraceAdapter(trace.get_arch(), trace.get_machine());
		if (!adapter) {
			throw RizinException("Failed to match frame_architecture %d and machine %llu to TraceAdapter.",
				(int)trace.get_arch(), (unsigned long long)trace.get_machine());
		}
		adapter->SetMachine(trace.get_machine());
		if (big_endian) {
			adapter->SetIsBigEndian(true);
		}
		if (dump_only) {
			DumpTrace(trace, offset, count, verbose, adapter.get());
			return 0;
		}

		RizinEmulator r(std::move(adapter));
		if (!cache_reset) {
			r.SetMem(trace);
		}
		r.SetPrettyIL(prettify_il);
		trace.seek(offset);
		std::array<uint64_t, FRAME_CHECK_RESULT_COUNT> stats = {};
		std::unique_ptr<RzSetU, decltype(&rz_set_u_free)> covered_insn_ids(rz_set_u_new(), rz_set_u_free);
		if (!covered_insn_ids) {
			throw RizinException("Failed to allocate instruction coverage set.");
		}
		std::vector<FrameReport> frame_reports;
		std::unique_ptr<frame> cur_frame = trace.get_frame();

		printf("\nCompare frames...\n");
		ut64 n = trace.get_num_frames();
		ut64 total = 0;
		ut64 frame_index = offset;
		while (cur_frame && !rz_cons_is_breaked() && count) {
			std::unique_ptr<frame> next_frame = trace.end_of_trace() ? nullptr : trace.get_frame();
			std::optional<ut64> next_pc = std::nullopt;
			if (next_frame && next_frame->has_std_frame()) {
				next_pc = next_frame->std_frame().address();
			}
			size_t tested_insn_id = 0;
			FrameReport frame_report;
			auto res = r.RunFrame(frame_index++, cur_frame.get(), next_pc, verbose,
				invalid_op_quiet, skip_by_disasm, &tested_insn_id, cache_reset,
				report_path ? &frame_report : nullptr);
			if (tested_insn_id) {
				rz_set_u_add(covered_insn_ids.get(), tested_insn_id);
			}
			if (report_path) {
				frame_report.result = res;
				frame_report.instruction_id = tested_insn_id;
				frame_reports.emplace_back(std::move(frame_report));
			}
			stats[static_cast<size_t>(res)]++;
			count--;
			total++;
			cur_frame = std::move(next_frame);
			if (fail_early && res != FrameCheckResult::Success && res != FrameCheckResult::Skipped) {
				break;
			}
			if (fail_unlifted && res == FrameCheckResult::Unimplemented) {
				break;
			}
			if (fail_runtime && res == FrameCheckResult::VMRuntimeError) {
				break;
			}
			if (fail_misexec && res == FrameCheckResult::PostStateMismatch) {
				break;
			}
			float done = n ? 100.00f * (float)total / (float)n : 100.0f;
			printf("\rFrames: %" PFMT64u " Done: %5.2f%%", n, done);
		}
		printf("\n");

		bool interrupted = rz_cons_is_breaked();
		bool semantic_failure = interrupted;
		for (size_t i = 0; i < stats.size(); i++) {
			FrameCheckResult result = static_cast<FrameCheckResult>(i);
			if (result != FrameCheckResult::Success && result != FrameCheckResult::Skipped && stats[i]) {
				semantic_failure = true;
			}
		}

		printf("\n--------------------------------------\n");
		for (size_t i = 0; i < stats.size(); i++) {
			switch (static_cast<FrameCheckResult>(i)) {
			case FrameCheckResult::Success:
				printf("              success: ");
				break;
			case FrameCheckResult::Skipped:
				printf("              skipped: ");
				break;
			case FrameCheckResult::InvalidOp:
				printf("           invalid op: ");
				break;
			case FrameCheckResult::Unimplemented:
				printf("             unlifted: ");
				break;
			case FrameCheckResult::InvalidIL:
				printf("           invalid il: ");
				break;
			case FrameCheckResult::VMRuntimeError:
				printf("     vm runtime error: ");
				break;
			case FrameCheckResult::PostStateMismatch:
				printf("          misexecuted: ");
				break;
			case FrameCheckResult::Unknown:
				printf("     unknown failures: ");
				break;
			}
			float percent = total ? 100.0f * (float)stats[i] / (float)total : 0.0f;
			if (semantic_failure && static_cast<FrameCheckResult>(i) == FrameCheckResult::Success && percent > 99.98f) {
				percent = 99.99f;
			}
			printf("%-7" PFMT64u " %5.2f%%\n", stats[i], percent);
		}

		size_t covered = rz_set_u_size(covered_insn_ids.get());
		printf("\nUnique instructions emulated: %" PFMTSZu "\n", covered);
		if (covered < 10) {
			printf("\nCovered instructions seem unreasonably low.\n");
			printf("Either RzAnalysisOp->id is not set by the arch plugin or binary is very small.\n");
		}

		if (report_path) {
			WriteJsonReport(*report_path, report_info, frame_reports, stats, covered, interrupted);
		}
		return strict_exit && semantic_failure ? 1 : 0;
	} catch (const std::exception &error) {
		eprintf("rz-tracetest: %s\n", error.what());
		if (report_path) {
			try {
				WriteJsonErrorReport(*report_path, error.what());
			} catch (const std::exception &report_error) {
				eprintf("rz-tracetest: %s\n", report_error.what());
			}
		}
		return strict_exit ? 2 : 1;
	} catch (...) {
		const char *message = "unknown input or configuration error";
		eprintf("rz-tracetest: %s\n", message);
		if (report_path) {
			try {
				WriteJsonErrorReport(*report_path, message);
			} catch (...) {
			}
		}
		return strict_exit ? 2 : 1;
	}
}
