# QEMU M68K translations that disagree with the official manuals

Rizin follows the Motorola M68000 Family Programmer’s Reference Manual.
QEMU is only a trace producer. When QEMU’s instruction translation is
wrong, we record it here and do **not** change Rizin to match QEMU.

| Instruction | QEMU behaviour | Manual behaviour | Evidence |
|---|---|---|---|
| `CMP2` | `target/m68k/translate.c` `DISAS_INSN(chk2)`: if extension bit 11 is clear, `EXCP_ILLEGAL`. | CMP2 compares Rn to the bound pair at EA and sets Z/C. It does not trap. CHK2 is the trapping variant (bit 11 set). | QEMU `translate.c` `ext & 0x0800` check. Exact-producer `cmp2` traces take the illegal trampoline. |
| `CHK2` helper | Implemented. Flag rule matches a real MC68040 (X/N/V unaffected; Z if equal to a bound; C if outside, including wrapped `lb > ub`). | Same CMP2/CHK2 flag rule. CHK2 traps if C is set. | QEMU `HELPER(chk2)` comment. Rizin sets the same Z/C. Exception *frames* are not compared (empty IL hook). |

Translator aborts while producing traces (`divs`, some `add`/`fmove`/`fcos`/`wdebug`) are producer crashes, not an oracle for Rizin.
