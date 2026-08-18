// SPDX-FileCopyrightText: 2026 Aya contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include "adapter.h"

#include <cassert>
#include <cstdint>
#include <string>

static uint16_t BitsToU16(const RzBitVector *value, size_t offset) {
	uint16_t result = 0;
	for (size_t i = 0; i < 16; i++) {
		if (rz_bv_get(value, offset + i)) {
			result |= static_cast<uint16_t>(1u << i);
		}
	}
	return result;
}

static RzBitVector *QemuFloat(uint16_t signexp, uint64_t significand,
	bool dirty_padding) {
	RzBitVector *value = rz_bv_new(96);
	rz_bv_set_from_ut64(value, significand);
	for (size_t i = 0; i < 16; i++) {
		rz_bv_set(value, 64 + i, dirty_padding);
		rz_bv_set(value, 80 + i, (signexp >> i) & 1);
	}
	return value;
}

static void TestMachines() {
	struct MachineCase {
			size_t machine;
			const char *cpu;
	};
	static const MachineCase machines[] = {
		{ frame_mach_m68000, "68000" },
		{ frame_mach_m68010, "68010" },
		{ frame_mach_m68020, "68020" },
		{ frame_mach_m68030, "68030" },
		{ frame_mach_m68040, "68040" },
		{ frame_mach_m68060, "68060" },
		{ frame_mach_mcf_isa_a, "cfv2" },
		{ frame_mach_mcf_isa_aplus_emac, "cfv2" },
		{ frame_mach_mcf_isa_b_float_emac, "cfv4e" },
	};

	for (const MachineCase &machine : machines) {
		auto adapter = SelectTraceAdapter(frame_arch_m68k, machine.machine);
		assert(adapter);
		assert(adapter->RizinArch() == "m68k");
		assert(adapter->RizinCPU() == machine.cpu);
		assert(adapter->RizinHaltOnExceptions() == "none");
		assert(adapter->RizinBits(std::nullopt, machine.machine) == 32);
		assert(adapter->IsBigEndian());
		assert(adapter->TraceRegToRizin("fp") == "a6");
		assert(adapter->TraceRegToRizin("sp") == "a7");
		assert(adapter->TraceRegToRizin("ps") == "sr");
		assert(adapter->TraceRegToRizin("fpcontrol") == "fpcr");
		assert(adapter->TraceRegToRizin("fpstatus") == "fpsr");
		assert(adapter->TraceRegToRizin("fpiaddr") == "fpiar");
		assert(adapter->TraceRegToRizin("D3") == "d3");
		assert(adapter->RegNeedsCustomHandling("fp0"));
		assert(adapter->RegNeedsCustomHandling("fp7"));
		assert(!adapter->RegNeedsCustomHandling("fp"));
		assert(adapter->AllowNoOperandSameValueAssignment());
	}

	assert(!SelectTraceAdapter(frame_arch_m68k, 0));
	assert(!SelectTraceAdapter(frame_arch_m68k, frame_mach_m68008));
	assert(!SelectTraceAdapter(frame_arch_m68k, frame_mach_cpu32));

	auto adapter = SelectTraceAdapter(frame_arch_m68k, frame_mach_m68020);
	adapter->SetRizinCPUOverride("cpu32");
	assert(adapter->RizinCPU() == "cpu32");
	RzBitVector *ps = rz_bv_new_from_ut64(32, 0xabcd1234);
	adapter->AdjustRegContentsFromTrace("ps", ps);
	assert(rz_bv_len(ps) == 16);
	assert(rz_bv_to_ut16(ps) == 0x1234);
	rz_bv_free(ps);
}

static void TestFloatConversions() {
	struct FloatCase {
		uint16_t signexp;
		uint64_t significand;
		uint64_t normalized_significand;
	};
	static const FloatCase values[] = {
		{ 0x0000, 0x0000000000000000ULL, 0x0000000000000000ULL }, // +0
		{ 0x8000, 0x0000000000000000ULL, 0x0000000000000000ULL }, // -0
		{ 0x4000, 0x8000000000000000ULL, 0x8000000000000000ULL }, // finite
		{ 0x7fff, 0x8000000000000000ULL, 0x8000000000000000ULL }, // +infinity
		{ 0xffff, 0x8000000000000000ULL, 0x8000000000000000ULL }, // -infinity
		{ 0x7fff, 0x0000000000000000ULL, 0x8000000000000000ULL }, // +pseudo-infinity
		{ 0x7fff, 0xc000000000000001ULL, 0xc000000000000001ULL }, // qNaN
	};

	for (const FloatCase &value : values) {
		RzBitVector *qemu = QemuFloat(value.signexp, value.significand, true);
		RzBitVector *rizin = M68KQemuFloatToRizin(qemu);
		assert(rizin);
		assert(rz_bv_len(rizin) == 80);
		assert(rz_bv_to_ut64(rizin) == value.normalized_significand);
		assert(BitsToU16(rizin, 64) == value.signexp);

		RzBitVector *roundtrip = M68KRizinFloatToQemu(rizin);
		assert(roundtrip);
		assert(rz_bv_len(roundtrip) == 96);
		assert(rz_bv_to_ut64(roundtrip) == value.normalized_significand);
		assert(BitsToU16(roundtrip, 80) == value.signexp);
		assert(BitsToU16(roundtrip, 64) == 0);

		rz_bv_free(roundtrip);
		rz_bv_free(rizin);
		rz_bv_free(qemu);
	}
	assert(!M68KQemuFloatToRizin(nullptr));
	assert(!M68KRizinFloatToQemu(nullptr));
	RzBitVector *invalid = rz_bv_new(80);
	assert(!M68KRizinFloatToQemu(invalid, 32));
	rz_bv_free(invalid);
}

static void TestFloatEventEquivalence() {
	auto adapter = SelectTraceAdapter(frame_arch_m68k, frame_mach_m68040);
	RzBitVector *qemu_payload = QemuFloat(0x7fff, UINT64_C(0xffffffffffffffff), false);
	RzBitVector *qemu_canonical = QemuFloat(0x7fff, UINT64_C(0xc000000000000001), false);
	RzBitVector *payload = M68KQemuFloatToRizin(qemu_payload);
	RzBitVector *canonical = M68KQemuFloatToRizin(qemu_canonical);
	RzFloat *old_float = RZ_NEW0(RzFloat);
	RzFloat *new_float = RZ_NEW0(RzFloat);
	assert(old_float && new_float);
	old_float->r = RZ_FLOAT_IEEE754_BIN_80;
	old_float->s = rz_bv_dup(payload);
	new_float->r = RZ_FLOAT_IEEE754_BIN_80;
	new_float->s = rz_bv_dup(canonical);
	RzILVal *old_value = rz_il_value_new_float(old_float);
	RzILVal *new_value = rz_il_value_new_float(new_float);
	RzILEvent *event = rz_il_event_var_write_new("fp2", old_value, new_value);
	assert(!adapter->AssumeEventIsJustified(event));
	rz_il_event_free(event);
	rz_il_value_free(new_value);
	rz_il_value_free(old_value);
	old_value = rz_il_value_new_bitv(rz_bv_dup(payload));
	new_value = rz_il_value_new_bitv(rz_bv_dup(canonical));
	event = rz_il_event_var_write_new("fp2", old_value, new_value);
	assert(!adapter->AssumeEventIsJustified(event));
	rz_il_event_free(event);
	rz_il_value_free(new_value);
	rz_il_value_free(old_value);
	rz_bv_free(canonical);
	rz_bv_free(payload);
	rz_bv_free(qemu_canonical);
	rz_bv_free(qemu_payload);
}

static void TestDoubleConversions() {
	static const uint64_t values[] = {
		UINT64_C(0x0000000000000000), // +0
		UINT64_C(0x8000000000000000), // -0
		UINT64_C(0x0000000000000001), // minimum subnormal
		UINT64_C(0x000fffffffffffff), // maximum subnormal
		UINT64_C(0x0010000000000000), // minimum normal
		UINT64_C(0x3ff0000000000000), // 1.0
		UINT64_C(0xc000000000000000), // -2.0
		UINT64_C(0x7fefffffffffffff), // maximum finite
		UINT64_C(0x7ff0000000000000), // +infinity
		UINT64_C(0xfff0000000000000), // -infinity
		UINT64_C(0x7ff8000000000001), // qNaN with payload
	};

	for (uint64_t value : values) {
		RzBitVector *qemu = rz_bv_new_from_ut64(64, value);
		RzBitVector *rizin = M68KQemuFloatToRizin(qemu);
		assert(rizin);
		assert(rz_bv_len(rizin) == 80);
		RzBitVector *roundtrip = M68KRizinFloatToQemu(rizin, 64);
		assert(roundtrip);
		assert(rz_bv_len(roundtrip) == 64);
		assert(rz_bv_to_ut64(roundtrip) == value);
		rz_bv_free(roundtrip);
		rz_bv_free(rizin);
		rz_bv_free(qemu);
	}

	RzBitVector *one = rz_bv_new_from_ut64(64, UINT64_C(0x3ff0000000000000));
	RzBitVector *extended_one = M68KQemuFloatToRizin(one);
	assert(BitsToU16(extended_one, 64) == 0x3fff);
	assert(rz_bv_to_ut64(extended_one) == UINT64_C(0x8000000000000000));
	rz_bv_free(extended_one);
	rz_bv_free(one);
}

static void TestNaNEquivalence() {
	RzBitVector *qemu_payload = QemuFloat(0x7fff, UINT64_C(0xffffffffffffffff), false);
	RzBitVector *qemu_canonical = QemuFloat(0x7fff, UINT64_C(0x8000000000000001), false);
	RzBitVector *qemu_negative = QemuFloat(0xffff, UINT64_C(0x8000000000000001), false);
	RzBitVector *qemu_infinity = QemuFloat(0x7fff, UINT64_C(0x8000000000000000), false);
	RzBitVector *payload = M68KQemuFloatToRizin(qemu_payload);
	RzBitVector *canonical = M68KQemuFloatToRizin(qemu_canonical);
	RzBitVector *negative = M68KQemuFloatToRizin(qemu_negative);
	RzBitVector *infinity = M68KQemuFloatToRizin(qemu_infinity);
	assert(!M68KRizinFloatsEquivalent(payload, canonical, 96));
	assert(M68KRizinFloatsEquivalent(payload, payload, 96));
	assert(!M68KRizinFloatsEquivalent(canonical, negative, 96));
	assert(!M68KRizinFloatsEquivalent(payload, infinity, 96));
	assert(!M68KRizinFloatsEquivalent(nullptr, canonical, 96));
	rz_bv_free(infinity);
	rz_bv_free(negative);
	rz_bv_free(canonical);
	rz_bv_free(payload);
	rz_bv_free(qemu_infinity);
	rz_bv_free(qemu_negative);
	rz_bv_free(qemu_canonical);
	rz_bv_free(qemu_payload);
}

int main() {
	TestMachines();
	TestFloatConversions();
	TestDoubleConversions();
	TestNaNEquivalence();
	TestFloatEventEquivalence();
	return 0;
}
