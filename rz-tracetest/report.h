// SPDX-FileCopyrightText: 2026 Aya contributors
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _REPORT_H
#define _REPORT_H

#include "rzemu.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct TraceReportInfo {
		uint64_t trace_version = 0;
		uint64_t architecture = 0;
		uint64_t machine = 0;
		uint64_t frame_count = 0;
};

const char *FrameCheckResultName(FrameCheckResult result);

void WriteJsonReport(const std::string &path, const TraceReportInfo &trace,
	const std::vector<FrameReport> &frames,
	const std::array<uint64_t, FRAME_CHECK_RESULT_COUNT> &summary,
	uint64_t unique_instructions, bool interrupted);

void WriteJsonErrorReport(const std::string &path, const std::string &message);

#endif
