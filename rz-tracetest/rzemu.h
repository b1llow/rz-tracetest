// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _RZEMU_H
#define _RZEMU_H

#include "adapter.h"

#include <rz_core.h>

#include <trace.container.hpp>

#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class RizinException : public std::exception {
	public:
		RizinException(const char *fmt, ...) {
			va_list ap, ap2;
			va_start(ap, fmt);
			va_copy(ap2, ap);
			int ret = vsnprintf(NULL, 0, fmt, ap2);
			ret++;
			msg = new char[ret];
			vsnprintf(msg, ret, fmt, ap);
			va_end(ap2);
			va_end(ap);
		}

		~RizinException() {
			delete[] msg;
		}

		const char *what() const noexcept override { return msg; }

	private:
		char *msg;
};

enum class FrameCheckResult {
	Success,
	Skipped,
	InvalidOp,
	InvalidIL,
	VMRuntimeError,
	PostStateMismatch,
	Unimplemented,
	Unknown
};
#define FRAME_CHECK_RESULT_COUNT 8

struct FrameValueDifference {
		std::string name;
		ut64 address = 0;
		bool has_address = false;
		std::string expected;
		std::string actual;
};

struct FrameReport {
		ut64 index = 0;
		ut64 address = 0;
		bool has_address = false;
		std::string bytes;
		std::string disassembly;
		FrameCheckResult result = FrameCheckResult::Unknown;
		size_t instruction_id = 0;
		std::vector<FrameValueDifference> register_differences;
		std::vector<FrameValueDifference> memory_differences;
		std::vector<std::string> details;
};

class RizinEmulator {
	private:
		std::unique_ptr<TraceAdapter> adapter;
		std::unique_ptr<RzCore, decltype(&rz_core_free)> core;
		std::unique_ptr<RzReg, decltype(&rz_reg_free)> reg;
		std::unique_ptr<RzAnalysisILVM, decltype(&rz_analysis_il_vm_free)> vm;
		std::unique_ptr<RzILValidateGlobalContext, decltype(&rz_il_validate_global_context_free)> validate_ctx;
		bool prettify_il;

		bool TraceRegOverlapsILVar(const char *tracereg, const char *var);

	public:
		RizinEmulator(std::unique_ptr<TraceAdapter> adapter);
		FrameCheckResult RunFrame(ut64 index, frame *f, std::optional<ut64> next_pc, int verbose, bool invalid_op_quiet,
			std::optional<std::function<bool(const std::string &)>> skip_by_disasm, size_t *tested_insn_id,
			bool cache_reset = true, FrameReport *report = nullptr);
		void SetPrettyIL(bool value) {
			this->prettify_il = value;
		}
		void SetMem(SerializedTrace::TraceContainerReader &trace);
		std::map<std::string, int> get_post_op_map(const std_frame &sf);
};

#endif
