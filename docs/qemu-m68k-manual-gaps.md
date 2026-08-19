# QEMU M68K translations that disagree with the official manuals

Rizin follows the Motorola M68000 Family Programmer’s Reference Manual.
QEMU is only a trace producer. When QEMU’s instruction translation is
wrong, we record it here and do **not** change Rizin to match QEMU.

| Instruction | QEMU behaviour | Manual behaviour | Evidence |
|---|---|---|---|
| `CMP2` | `target/m68k/translate.c` `DISAS_INSN(chk2)`: if extension bit 11 is clear, `EXCP_ILLEGAL`. The plugin then often records only the 2-byte opcode. | CMP2 compares Rn to the bound pair at EA and sets Z/C. It does not trap. CHK2 is the trapping variant (bit 11 set). | QEMU `translate.c` `ext & 0x0800` check. Exact-producer `cmp2` traces take the illegal trampoline. |
| `CHK2` helper | Implemented. Flag rule matches a real MC68040 (X/N/V unaffected; Z if equal to a bound; C if outside, including wrapped `lb > ub`). | Same CMP2/CHK2 flag rule. CHK2 traps if C is set. | QEMU `HELPER(chk2)` comment. Rizin sets the same Z/C. Exception *frames* are not compared (empty IL hook). |
| `MOVEC CAAR` | `HELPER(m68k_movec_to/from)` `cpu_abort` on CAAR. | 68020/68030 implement CAAR as a 32-bit control register. | QEMU `target/m68k/helper.c` unimplemented-register abort. |
| User-mode `MOVES`/`MOVEC` length | Privilege check fires before the extension word is fetched, so the captured encoding is 2 bytes. | Both instructions are 4+ bytes; user mode takes a privilege exception after fetching the whole instruction. | QEMU `DISAS_INSN(moves)` / `m68k_movec` `IS_USER` return before `read_im16`. |
| `MOVEC PCR` / `BUSCR` | `HELPER(m68k_movec_to/from)` `cpu_abort`. | 68060 implements PCR and BUSCR. | QEMU `target/m68k/helper.c` unimplemented-register abort. |
| `MOVEC ITT0/1` `DTT0/1` on 68060 | Helper only accepts them when `M68K_FEATURE_M68040` is set, so 68060 takes illegal. | 68060 has the same four transparent translation registers. | QEMU `helper.c` ITT/DTT feature test. |
| `FSAVE` / `FRESTORE` on 68020/68030 | `DISAS_INSN(fsave/frestore)` is 68040-only idle (`0x41000000`); otherwise `disas_undef`. | 68020 writes a 68881 idle/null/busy frame (idle 28 bytes, format `$1F18`); 68030 writes 68882 (idle 60 bytes, `$1F38`). | QEMU `translate.c` `m68k_feature(..., M68K_FEATURE_M68040)` before `DEST_EA`/`SRC_EA`. |
| `FSAVE` on 68040 | Always writes the idle longword; busy/unimplemented frames are never produced. | Idle `$4100` (4 bytes), unimplemented `$4130` (52 bytes), busy `$B400` (96 bytes). | QEMU `DISAS_INSN(fsave)` comment “always write IDLE”. |
| MAC with load, `An` writeback | Postincrement/predecrement uses the **MASK-ed** address (QEMU `FIXME`). | ColdFire PRM: load from `EA & MASK`; `(An)+`/`-(An)` write back the **unmasked** EA, and the parallel load is always a longword. | QEMU `DISAS_INSN(mac)` writeback from `addr` after `and MASK`. |
| MAC `MASK` reset | `mac_mask` is left 0 by CPU reset. | ColdFire reset value is `$FFFFFFFF`; writes force the high 16 bits to 1. | QEMU `cpu.c` has no MASK reset; `to_mask` does `ORI 0xffff0000`. |
| MAC `MACSR` S/U | `gen_mac_extract_word`: `MACSR_SU` set → signed (`ext16s` / `macmuls`); clear → unsigned. | CFPRM integer mode: `S/U,F/I==00` signed, `==10` unsigned. `S/U=0` is signed. | QEMU `translate.c` `MACSR_SU` polarity. |

Translator aborts while producing traces (`divs`, some `add`/`fmove`/`fcos`/`wdebug`) are producer crashes, not an oracle for Rizin.
