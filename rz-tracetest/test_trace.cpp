// SPDX-FileCopyrightText: 2026 Aya contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include <trace.container.hpp>

#include <cstdio>
#include <cstdint>
#include <string>

using namespace SerializedTrace;

static meta_frame TestMetadata() {
	meta_frame meta;
	meta.mutable_tracer()->set_name("rz-tracetest test");
	meta.mutable_tracer()->set_version("1");
	meta.mutable_target()->set_path("test");
	meta.mutable_target()->set_md5sum("");
	meta.mutable_fstats()->set_size(0);
	meta.mutable_fstats()->set_atime(0);
	meta.mutable_fstats()->set_mtime(0);
	meta.mutable_fstats()->set_ctime(0);
	meta.set_user("test");
	meta.set_host("localhost");
	meta.set_time(0);
	return meta;
}

static operand_info *AddRegister(operand_value_list *list, const char *name,
	uint32_t value, bool read, bool written) {
	operand_info *operand = list->add_elem();
	operand->mutable_operand_info_specific()->mutable_reg_operand()->set_name(name);
	operand->set_bit_length(32);
	operand->mutable_operand_usage()->set_read(read);
	operand->mutable_operand_usage()->set_written(written);
	operand->mutable_operand_usage()->set_index(false);
	operand->mutable_operand_usage()->set_base(false);
	operand->mutable_taint_info()->set_no_taint(true);
	char bytes[4] = {
		static_cast<char>(value),
		static_cast<char>(value >> 8),
		static_cast<char>(value >> 16),
		static_cast<char>(value >> 24),
	};
	operand->set_value(bytes, sizeof(bytes));
	return operand;
}

static operand_info *AddMemory(operand_value_list *list, uint64_t address,
	uint16_t value, bool read, bool written) {
	operand_info *operand = list->add_elem();
	operand->mutable_operand_info_specific()->mutable_mem_operand()->set_address(address);
	operand->set_bit_length(16);
	operand->mutable_operand_usage()->set_read(read);
	operand->mutable_operand_usage()->set_written(written);
	operand->mutable_operand_usage()->set_index(false);
	operand->mutable_operand_usage()->set_base(false);
	operand->mutable_taint_info()->set_no_taint(true);
	char bytes[2] = {
		static_cast<char>(value),
		static_cast<char>(value >> 8),
	};
	operand->set_value(bytes, sizeof(bytes));
	return operand;
}

static void WriteTrace(const char *path, uint64_t machine, uint32_t expected_pc) {
	frame trace_frame;
	std_frame *standard = trace_frame.mutable_std_frame();
	standard->set_address(0x1000);
	standard->set_thread_id(0);
	standard->set_rawbytes("\x4e\x71", 2);
	AddRegister(standard->mutable_operand_pre_list(), "ps", 0x2000, true, false);
	AddRegister(standard->mutable_operand_post_list(), "pc", expected_pc, false, true);

	TraceContainerWriter writer(path, TestMetadata(), frame_arch_m68k, machine, 64);
	writer.add(trace_frame);
	writer.finish();
	// The v3 reader consumes one trailing TOC slot for a partial bucket.
	// TraceContainerWriter predates that reader behavior, so complete the slot
	// exactly as current tracers do. Frame zero never seeks through this entry.
	FILE *output = fopen(path, "ab");
	if (!output) {
		throw TraceException("Unable to reopen test trace");
	}
	uint64_t trailing_toc_offset = 0;
	if (fwrite(&trailing_toc_offset, sizeof(trailing_toc_offset), 1, output) != 1 ||
		fclose(output) != 0) {
		throw TraceException("Unable to complete test trace TOC");
	}
}

static void WriteMemoryTrace(const char *path) {
	frame trace_frame;
	std_frame *standard = trace_frame.mutable_std_frame();
	standard->set_address(0x1000);
	standard->set_thread_id(0);
	standard->set_rawbytes("\x33\xfc\x01\x00\x00\xa1\x00\x00", 8);
	AddRegister(standard->mutable_operand_pre_list(), "ps", 0x2015, true, false);
	AddMemory(standard->mutable_operand_post_list(), 0xa10000, 0x0100, false, true);
	AddRegister(standard->mutable_operand_post_list(), "ps", 0x2010, false, true);
	AddRegister(standard->mutable_operand_post_list(), "pc", 0x1008, false, true);

	TraceContainerWriter writer(path, TestMetadata(), frame_arch_m68k, frame_mach_m68040, 64);
	writer.add(trace_frame);
	writer.finish();
	FILE *output = fopen(path, "ab");
	if (!output) {
		throw TraceException("Unable to reopen memory test trace");
	}
	uint64_t trailing_toc_offset = 0;
	if (fwrite(&trailing_toc_offset, sizeof(trailing_toc_offset), 1, output) != 1 ||
		fclose(output) != 0) {
		throw TraceException("Unable to complete memory test trace TOC");
	}
}

int main(int argc, char **argv) {
	if (argc != 5) {
		return 2;
	}
	WriteTrace(argv[1], frame_mach_m68020, 0x1002);
	WriteTrace(argv[2], frame_mach_m68020, 0x1004);
	WriteTrace(argv[3], 0, 0x1002);
	WriteMemoryTrace(argv[4]);
	return 0;
}
