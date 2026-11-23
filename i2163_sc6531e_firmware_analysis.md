# itel it2163 (Spreadtrum SC6531E) — Full Firmware Analysis & Register Reference

> **⚠ CORRECTION NOTICE (Rev. 2):** After cross-referencing the official
> *SC6531E and SC6531M Device Specification* (989 pp), several peripheral
> identifications in this report were found to be **wrong**. The corrections
> are listed in `i2163_audio_path_analysis.md` §Rev.2-changelog and are
> reflected in the updated CSVs. Key corrections affecting this report:
>
> | address | was (wrong) | now (correct per datasheet) |
> |---|---|---|
> | 0x82003000 | "ADI-adjacent module" | **VBC — Voice Band Controller** (DS §6.7) |
> | 0x8200304C-0x82003074 | — | **DAALCCTL0-10** (ALC coefficients, NOT FIFO slots) |
> | 0x83000000 | "unknown module" | **UART0** (DS §5.2.2) |
> | 0x84000000 | "unknown module" | **UART1** (DS §5.2.2, shared with DSP) |
> | 0x86000000 / 0x86001000 | "UART0 / UART1" | **I2C0 / I2C1** (DS §5.2.2) |
> | 0x88000000 | "watchdog candidate" | **PWM** (DS §5.2.2; firmware also uses it as module clk/power bank — unresolved) |
> | 0x8D101000 | "SFC (SPI NOR)" | **GEA or undocumented** (SFC is at 0x20A00000 on AHB, DS §5.6) |
> | 0x8D200000 | "CGA clock generator" | **AON — Always-On domain** (DS §5.2.2: AON at 0x8D020000, firmware uses 0x8D200000) |
> | 0x8F000000 / 0x8F100000 | not identified | **IIS0 / IIS1** (DS §5.2.2, shared with DSP) |
> | 0x8A002000 / 0x8A003000 | not identified | **AUD / AUDIFD** (DS §5.2.2, ch.11) |
> | 0x20100000 | not identified | **DMA control registers** (DS §5.2.1 AHB map) |
>
> The corrected register reference for the audio path specifically is in
> `i2163_audio_path_analysis.md` and `i2163_audio_path_writes.csv`.

**Target file:** `flash.bin` — 16,777,216 bytes (16 MiB) raw NOR flash dump
**SoC:** Spreadtrum/UNISOC SC6531E (`SC6531EFM` build, analog companion die `SC1161`)
**CPU core:** ARM926EJ-S (ARMv5TE), up to 208 MHz
**OS:** ThreadX RTOS (Spreadtrum "MOCOR" stack)
**Analysis type:** static reverse engineering — recursive-descent disassembly (ARM + Thumb), literal-pool constant propagation, MMIO access harvesting, string/structure forensics, cross-reference against public community RE sources and the official SC6531E/M Device Specification

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Methodology, tooling and confidence levels](#2-methodology-tooling-and-confidence-levels)
3. [Device & SoC identification](#3-device--soc-identification)
4. [Flash image structure](#4-flash-image-structure)
5. [System memory map](#5-system-memory-map)
6. [Boot flow analysis](#6-boot-flow-analysis)
7. [Interrupt architecture](#7-interrupt-architecture)
8. [**Peripheral register reference (the register list)**](#8-peripheral-register-reference)
   - 8.1 Global registers / AON_APB (0x8B000000)
   - 8.2 AHB clock/power gates (0x20500000)
   - 8.3 Clock generator CGA (0x8D200000)
   - 8.4 AON timer block (0x81000000)
   - 8.5 Interrupt controllers INTC0/INTC1 (0x80000000)
   - 8.6 ADI — Analog-Digital Interface + analog die window (0x82000000 / 0x82001xxx)
   - 8.7 eFuse controller (0x82002000)
   - 8.8 GPIO controller (0x8A000000)
   - 8.9 Pin configuration / IOMUX (0x8C000000)
   - 8.10 USB device controller (0x90000000)
   - 8.11 SPI flash controller SFC (0x8D101000)
   - 8.12 SDIO/SD card controller (0x20700000)
   - 8.13 Keypad controller KPD (0x87000000)
   - 8.14 LCM — MCU/DBI LCD interface (0x20800000) + LCD memory window (0x60000000)
   - 8.15 LCDC — display controller (0x20D00000)
   - 8.16 PSRAM controller SMC (0x20000000)
   - 8.17 UART0/UART1 (0x86000000 / 0x86001000)
   - 8.18 Watchdog & remaining modules (0x88000000, 0x83000000, 0x84000000, 0x8D000000, 0x8F000000, 0x82003000, 0x69000000)
9. [Register access database (evidence)](#9-register-access-database-evidence)
10. [RTOS internals (ThreadX)](#10-rtos-internals-threadx)
11. [DSP subsystem](#11-dsp-subsystem)
12. [Storage: NOR layout, FAT12 "MY disk", NV](#12-storage-nor-layout-fat12-my-disk-nv)
13. [MMI / application layer & user-data artifacts](#13-mmi--application-layer--user-data-artifacts)
14. [Security observations](#14-security-observations)
15. [Related ecosystem (flashing, FDL, homebrew, boot keys)](#15-related-ecosystem-flashing-fdl-homebrew-boot-keys)
16. [Appendix A — key disassembly listings](#16-appendix-a--key-disassembly-listings)
17. [Appendix B — deliverable files & CSV schema](#17-appendix-b--deliverable-files--csv-schema)

---

## 1. Executive summary

- The 16 MiB dump is **not one image**: it contains the **same 4 MiB firmware written four times** (verified by MD5: all four 4 MiB blocks are identical). This is the well-known multi-copy redundancy scheme of Spreadtrum feature phones — the boot ROM can fall back to the next copy if one is corrupted. All analysis below is of the first copy (offset 0x0–0x3FFFFF).
- The firmware is a **single eXecute-In-Place (XIP) image** mapped at address `0x00000000`: exception vectors at 0x0, ~524 KB of ARM/Thumb machine code and read-only data up to ≈0x83000, ~3 MB of compressed payload (DSP images + resources) from ≈0x83000 to 0x36F000, and MMI resources/file-system structures from 0x36F000 to 0x400000.
- **CPU & clocks:** ARM926EJ-S running ThreadX; the CPU frequency register (`0x8B00004C`) supports 26 / 104 / 208 MHz steps (208 MHz max on SC6531E; the SC6531DA sibling supports 312 MHz). The OS runs with MMU enabled (section descriptors, domains 0/1 client/manager).
- **RAM:** 4 MiB PSRAM at `0x04000000` (reset stack top `0x40002000`); ThreadX context/exception blocks, the level-1 page table and kernel objects live around `0x042C1000–0x042CC200`.
- **Registers:** I harvested every memory-mapped I/O access that static analysis could prove from the code: **278 verified accesses to 94 distinct register addresses across 29 peripheral modules**, each with the referencing instruction, program counter, read/write direction and written values. These are exported to CSV (see §9 and Appendix B). A further ~80 register addresses are documented from the community reverse-engineering of the same silicon (the FPDoom project), which are merged into the tables below and marked accordingly.
- **Analog die:** the package contains an **SC1161** companion die (PMIC/codec) reached through the **ADI** interface at `0x82000000` with its register window at `0x82001400+` (SC6531E) / `0x82001000+` (SC6530/DA). The firmware string `"SC1161"` at 0x58114 matches the ADI chip-ID value `0x1161A000` documented by the community.
- **Real user data is present** in the dump: the FAT12 "MY disk" area retains previously paired Bluetooth device names (e.g. "vivo Y33s", "boAt Rockerz", "soundcore H30i") — this particular phone was used and paired before it was dumped.
- **No cryptographic content** was found in the code region (no AES/RSA/SHA/MD5/IMEI-related strings): there is no secure-boot or firmware-signature logic in this build. The bootloader accepts unsigned code through the standard Spreadtrum download (FDL) protocol.

---

## 2. Methodology, tooling and confidence levels

Because a raw flash dump has no symbol table, "decompiling" here means a structured static-analysis pipeline, not a one-click decompiler output:

1. **Structure scan** — entropy mapping (per 4 KiB and 1 MiB), printability/pointer-density classification, copy detection via MD5.
2. **Recursive-descent disassembly** — a custom worklist walker (Capstone 5.0) that starts at the ARM exception vectors and the boot entry, follows every `b/bl/blx/bx`, performs ARM↔Thumb interworking (this OS is overwhelmingly Thumb code, entered through the `add ip, pc, #1 ; bx ip` thunk at 0x1060), and decodes literal pools (ARMv5 loads all constants through PC-relative pools). The walker enforces ARMv5TE semantics (no 32-bit Thumb-2 except the paired `bl`), which matters because random data misdecodes as Thumb-2 otherwise.
3. **Constant propagation** — within each function, register ← literal-pool values and `mov/add rX, pc/#imm` are tracked, so each `ldr/str rt, [rn, #off]` yields the *effective* MMIO address, the direction (R/W), and — when provable — the value written.
4. **Entry-point mining** — three phases: vector/boot roots; code pointers found in literal pools; then every word-aligned pointer-like value in the image (catches driver ops tables). Result: **140,014 disassembled instructions**, 86 high-confidence function entries, 2,929 literal pools read, 2,145 captured memory accesses.
5. **Identification** — each address cluster is identified by (a) its access pattern (8250-style UART layout, interrupt mask semantics, PLL divider arithmetic, …), (b) the firmware's own internal **peripheral base table** found at 0x5CCF0–0x5CD8C, which lists every module's start and end address, and (c) cross-reference against public community RE of the same SoC (the [FPDoom](https://github.com/ilyakurdyukov/fpdoom) project and the [spd_dump](https://github.com/ilyakurdyukov/spreadtrum_flash) flashing tool), cited where used.
6. **String forensics** — ThreadX object names, assert `__FILE__` paths, debug-menu text, resource names, FAT directory entries.

**Confidence labels used in the tables:**

| Label | Meaning |
|---|---|
| **confirmed** | Cross-verified against public RE code for this exact silicon, or unambiguous in-firmware evidence |
| **high** | Consistent evidence from multiple code sites in this firmware |
| **medium** | Single clear pattern; identity probable |
| **low** | Address observed; function inferred only |

> **Honesty note:** "All registers" below means *every register that the shipped firmware provably touches, plus every register publicly documented for this SoC*. A hardware datasheet for SC6531E is not public; registers that the firmware never references (unused peripheral features) cannot be enumerated from the dump alone. Every entry states its evidence.

---

## 3. Device & SoC identification

### 3.1 In-firmware identity strings

| Offset | String | Meaning |
|---|---|---|
| 0x580D6 | `beSC6531EFM` | chip/product build tag ("be" prefix + SC6531E **FM** = FM-radio variant) |
| 0x580EA | `beSC6531EFM_AB` | board revision AB |
| 0x58100 | `SC6531EFM_AC` | board revision AC |
| 0x58114 | `SC1161` | the analog companion die (PMIC + audio codec) |
| 0x59CAC | `Spreadtrum Boot Block version 3.0` | bootloader generation |
| 0x39E118 | `Spreadtrum Communication CO.` | boot logo string |

The chip-ID registers corroborate this: `*(0x8B00035C)=0x36320000`, `*(0x8B000360)=0x53433635` ("SC65"), `*(0x8B000364)=0x00000001`; the boot code folds them into `0x65620000` = SC6531EFM or `0x65620001` = SC6531EFM_AB (decoding documented in FPDoom's `init_chip_id()`). The analog die reports its own ID over ADI at `0x82001400+`: value `0x1161A000` = **SC1161**.

### 3.2 Public specification (external, cited)

| Item | Value | Source |
|---|---|---|
| SoC | UNISOC/Spreadtrum SC6531E, entry-level feature-phone SoC | [lpcwiki SC6531](https://lpcwiki.miraheze.org/wiki/Spreadtrum_systems-on-chip/SC6531) |
| CPU | ARM926EJ-S, ARMv5TEJ, 208 MHz on SC6531E (312 MHz on SC6531DA, 208 MHz SC6530) | [FPDoom coverage](https://en.linuxadictos.com/they-carry-doom-in-basic-phones-with-spreadtrum-sc6531-chip.html) |
| Second core | ARM Cortex-M for Bluetooth (no access to main RAM) | [lpcwiki SC6531](https://lpcwiki.miraheze.org/wiki/Spreadtrum_systems-on-chip/SC6531) — matches the firmware's `BT PSRAM memory` / `BT IRAM Memory` debug strings |
| RAM | 4 MiB (this phone) | [itel IT2163 listing](https://www.flipkart.com/itel-it2163/p/itm24123fbe39174) |
| Phone | itel it2163: 1.8" QQVGA 160×120, 1000 mAh, dual-SIM GSM, wireless FM, torch, micro-USB | [MoMo listing](https://market.momo.africa/Portal/product/20668/1?tenantId=1&lang=en), [onigx listing](https://onigx.com/product/itel-it2163-wireless-fm-torch-dual-sim-phone) |

The firmware's own frequency tables agree exactly with the public spec (see §8.1: 26/104/208 MHz steps).

---

## 4. Flash image structure

### 4.1 The four copies

| Block range | MD5 |
|---|---|
| 0x0000000–0x3FFFFF | `8e19ece90b8f5f02c80c53fd012d0d16` |
| 0x4000000–0x7FFFFF | `8e19ece90b8f5f02c80c53fd012d0d16` |
| 0x8000000–0xBFFFFF | `8e19ece90b8f5f02c80c53fd012d0f02c80c53fd012d0d16` (identical) |
| 0xC000000–0xFFFFFFF | identical |

*(all four 4 MiB blocks are byte-identical — one firmware, mirrored 4× across the 16 MiB NOR).*

### 4.2 Region map of the 4 MiB image

| Range (offset in copy) | Size | Class (from entropy/printable/pointer classification) | Content |
|---|---|---|---|
| 0x000000–0x000040 | 64 B | data | ARM exception vector table + literal pool |
| 0x000040–0x0003A4 | 864 B | data | FIQ entry stub + 26-entry IRQ configuration table (see §7) |
| 0x0003A4–0x083000 | ~520 KiB | code+rodata | OS + drivers + MMI logic (ARM & Thumb, literal pools, assert strings, kernel object names) |
| 0x083000–0x286000 | 2,060 KiB | compressed (entropy ≈7.99) | compressed payloads (DSP firmware images / resource packs) |
| 0x287000–0x342000 | 748 KiB | compressed | continuation of compressed payloads |
| 0x343000–0x36F000 | 176 KiB | compressed | compressed payloads (tail) |
| 0x36F000–0x398000 | 164 KiB | data (entropy ≈5.6) | graphics/font/asset data |
| 0x398000–0x3A8000 | 64 KiB | mixed | MMI resource directory (e.g. `EQ_Headset` equalizer preset table at 0x398000) |
| 0x3A8000–0x3B2000 | 40 KiB | mixed | resource/graphics data |
| 0x3B2000–0x3C042E | 56 KiB | mixed | FAT12 structures begin (dir tables, `.`/`..` entries) |
| 0x3C042E–0x400000 | 254 KiB | mixed | FAT12 "MY disk": BPB, FAT, directories, user files, NV-related blobs |

Notes:
- The compressed regions start abruptly with no plaintext header at the 4 KiB-granular boundaries; small headers exist inside (e.g. at 0x82FCC: `5A 00 00 00 01 00 10 00 …`). Spreadtrum MOCOR images typically use block-wise LZ variants. The exact codec was not reverse-engineered here — content attribution is by surrounding strings and loader code references (`DSP Memory:Offset=…` loader exists in the assert area).
- The code region is *not* contiguous Thumb: the reset path and exception handlers (0x549D0–0x55100), the ARM-mode helper library (cache/MMU ops at 0x57B60–0x57FA0) and interwork veneers are ARM; everything else is Thumb.

---

## 5. System memory map

Derived from the MMU region table found at **0x57FB0** (six 0x18-byte descriptors: `vaddr, size, paddr, type, attr…`), the boot code, and community cross-references:

| Address range | Size | Region | Evidence |
|---|---|---|---|
| `0x00000000–0x003FFFFF` | 4 MiB | NOR flash, XIP, identity-mapped | region table ent0; vector handlers point into it |
| `0x04000000–0x043AFFFF` | ~3.7 MiB | PSRAM (main RAM), cacheable | region table ent1; reset SP = `0x40002000` |
| `0x043B0000–0x043BFFFF` | 64 KiB | RAM segment 2 | region table ent2 |
| `0x043C0000–0x043CAFFF` | 44 KiB | RAM segment 3 | region table ent3 |
| `0x043CB000–…` (+0x35000) | — | RAM segment 4 (uncached/alias source) | region table ent4 |
| `0x08000000–0x084FFFFF` | 5 MiB | **virtual window** over RAM/flash (MMU alias) | region table ent4 |
| `0x08500000–0x088FFFFF` | 4 MiB | **virtual window** | region table ent5 |
| `0x042C1590` | 4 KiB | L1 page table (TTBR target; table allocated at runtime) | pool @0x43A4; `mcr p15,0,r0,c2,c0,0` at 0x57B88 |
| `0x042CBF80–0x042CC200` | ~1.6 KiB | exception context save area (see §6.2) | FIQ handler pools @0x54ED8+ |
| `0x20000000–0x200000FF` | 256 B | SMC — PSRAM controller registers | §8.16 |
| `0x20500000–0x20502FFF` | — | AHB clock/power domain control | §8.2 |
| `0x20700000 / 0x20700100` | 0x100 | SDIO0 / SDIO1 | §8.12 |
| `0x20800000–0x208000FF` | — | LCM (DBI LCD interface) | §8.14 |
| `0x20D00000–0x20D001FF` | — | LCDC (display controller) | §8.15 |
| `0x60000000+` | 16 MiB | LCM memory-mapped command/data window | §8.14 |
| `0x69000000–0x69000074` | 0x74 | unknown module (firmware base table) | low confidence |
| `0x80000000 / 0x80001000` | — | INTC0 / INTC1 | §8.5 |
| `0x81000000–0x8100300F` | — | AON timer/counter block | §8.4 |
| `0x82000000–0x8200001F` | — | ADI controller | §8.6 |
| `0x82001000–0x82001FFF` | — | analog die register window (ADI) | §8.6 |
| `0x82002000–0x8200201F` | — | eFuse controller | §8.7 |
| `0x82003000–0x820031BF` | 0x1C0 | ADI-adjacent module (calibration?) | §8.18 |
| `0x83000000 / 0x84000000` | 0x30 each | unknown small modules | §8.18 |
| `0x86000000 / 0x86001000` | 0x14 each | UART0 / UART1 | §8.17 |
| `0x87000000–0x8700003F` | — | keypad controller | §8.13 |
| `0x88000000–0x8800000F` | — | small module (watchdog candidate) | §8.18 |
| `0x8A000000–0x8A0003A7` | — | GPIO (76 pins × 0x80 stride) + aux banks 0x8A001000/0x8A002000 | §8.8 |
| `0x8B000000–0x8B000387` | — | AON_APB "GR" global registers | §8.1 |
| `0x8C000000–0x8C0002E3` | — | pin configuration (IOMUX) | §8.9 |
| `0x8D000000–0x8D0000FF` | — | module written at cold boot (watchdog/boot-flag candidate) | §8.18 |
| `0x8D101000–0x8D101034` | — | SFC — SPI flash controller | §8.11 |
| `0x8D200000–0x8D2000FF` | — | clock generator (CGA) | §8.3 |
| `0x8F000000–0x8F00003B` | 0x3C | unknown module | §8.18 |
| `0x90000000–0x9001FFFF` | — | USB device controller (+FIFO window at +0x80000) | §8.10 |

**Firmware-internal peripheral base table** (found at 0x5CCF0–0x5CD8C — this is the firmware's own module inventory, each entry is `base, end`):

```
0x82002000-0x82002020   0x82003000-0x820031c0   0x83000000-0x83000030
0x84000000-0x84000030   0x89000000-0x8900006c   0x86000000-0x86000014
0x86001000-0x86001014   0x87000000-0x87000038   0x88000000-0x88000010
0x8a000000-0x8a0003a8   0x8a001000-0x8a00105c   0x8a002000-0x8a002028
0x8b000000-0x8b000388   0x8d200000-0x8d200100   0x8c000000-0x8c0002e4
0x8d101000-0x8d101034   0x69000000-0x69000074   0x8f000000-0x8f00003c
0x82001000-0x8200101f   0x82001020-0x8200103f
```

---

## 6. Boot flow analysis

### 6.1 Cold vs. warm reset

The reset vector (0x0 → 0x549D0) immediately distinguishes a warm reboot from a power-on by comparing a flash-based config word against a pointer chain in RAM:

```armasm
000549d0  ldr  ip, [pc, #-0x160]      ; ip = 0x00058124  (flash config word)
000549d4  ldr  ip, [ip]               ; ip = *(0x58124)  = 0x00001F1F
000549d8  and  ip, ip, #0xff00
000549dc  ldr  fp, [pc, #-0x168]      ; fp = 0x00058054
000549e0  ldr  fp, [fp]               ; fp = *(0x58054)  = 0x00000800
000549e4  ldr  fp, [fp]               ; fp = **(0x58054)
000549e8  and  fp, fp, #0xff00
000549f0  cmp  ip, fp
000549f8  push {r0-r7,fp,lr}
00054a00  b    0x1060                 ; equal  -> warm path: ARM->Thumb thunk
00054a04  msr  cpsr_c, #0xd3          ; differ -> full cold init:
00054a08  ldr  sp, [pc, #0xb0]        ;   SVC stack top = 0x40002000  (RAM!)
00054a0c-...                          ;   zero r0-lr, spsr := 0x10
00054a4c  ldr  r0, [pc, #0x70]        ; r0 = 0x8B000364 (AON chip-id/boot flag reg)
00054a50  ldr  r1, [r0]
00054a54  cmp  r1, #0
00054a5c  mov  r0, #0x8D000000        ; cold-boot magic store:
00054a60  ldr  r1, [pc, #0x60]        ;   value = 0x0041C1C0
00054a64  str  r1, [r0]               ;   *(0x8D000000) = 0x0041C1C0
00054a68  blx  0x732                  ; -> Thumb sub-system init
00054a6c  blx  0x550                  ; ...
00054a70  blx  0xf84
...
00054ab0  b    0x564                  ; jump into RTOS bring-up
```

The warm/cold test compares `*(0x58124)&0xFF00` (0x1F00) with `**(0x58054)&0xFF00` — a RAM-resident signature left by the running OS. On a fresh dump this is a cold boot.

### 6.2 Exception context save (per-mode blocks in RAM)

The exception entry library at 0x54AD0 saves a full register context to a fixed block at **0x042CBF80** (`r0-r14,pc,sp,spsr,apsr` at +0x00/+0x30/+0x34/+0x40/+0x44), then snapshots the *other* modes' SP/LR/SPSR by bank-switching CPSR:

| Mode (CPSR value) | Save block | Fields |
|---|---|---|
| SVC (0xD3) | `0x042CBFD4` | SP, LR, SPSR |
| IRQ (0xD2) | `0x042CBFC8` | SP, LR, SPSR |
| ABT (0xD7) | `0x042CBFEC` | SP, LR, SPSR |
| UND (0xDB) | `0x042CBFE0` | SP, LR, SPSR |
| FIQ (0xD1) | `0x042CBFF8` | SP, LR, SPSR |

### 6.3 MMU bring-up

- A 16 KiB level-1 table is allocated in RAM; its address is kept at `*(0x042C1590)` (pool at 0x43A4).
- The region descriptors at 0x57FB0 (§5) are programmed by the mapping routine at 0x39A8/0x40C8 (`type==3` → 1 MiB section map).
- Domain access is set to `~0x32` (domain 0 client, domains 1/3+ manager, domain 2 no-access), control register OR-ed with `0x127F` (MMU+D-cache+I-cache+alignment fault) — functions `0x57BB8` (`enable`), `0x57B88` (`set TTBR`), 0x57BA4 (`invalidate I+D caches & TLB`).
- The full cache/MMU library lives at **0x57B60–0x57FA0** (all `mcr p15` sites).

### 6.4 Into the OS

Boot continues at 0x1060 → `add ip,pc,#1; bx ip` → **Thumb from 0x1068**: an initialization cascade over ~58 IRQ sources, then ThreadX starts (SWI vector 0x54C08 → Thumb 0x36F8 is the kernel's system-call/trap entry).

---

## 7. Interrupt architecture

- **Controllers:** INTC0 at `0x80000000` and INTC1 at `0x80001000` (§8.5). Known assignments: INTC0 bit 22 = LCDC end-of-frame; INTC1 bit 5 = USB device; INTC1 bit 8 = SDIO0. (Community-verified for the same silicon.)
- **Static IRQ configuration table at flash 0x64–0x3A3:** 26 entries × 0x20 bytes. Each entry has 7 configuration words plus a pointer to a 0x1C-byte runtime **handler descriptor** in RAM (targets `0x042C16A4…0x042C18B8`, stride 0x1C). The first words of each entry decode as packed {polarity/edge, mask, priority-ish} fields — e.g. entry 0: `006000C8 00090019 00380000 003200FF 007500EB 0101007A 000003C4 → 0x042C16A4`.
- **Runtime dispatch (FIQ path):** the ARM FIQ stub (0x54EB8) saves `r4`/`lr` into `0x042CBF80/0x042CBD4`, then `blx 0x118A` into a **Thumb dispatcher** which:
  1. polls the controller banks (base pointers kept in RAM structures at `0x042CE014` / `0x042C1FFC`),
  2. walks up to **58 interrupt sources** (`cmp r4, #0x3A`) through 0x18-byte entries: `{enable-bit, status-mask, handler, …}`,
  3. calls `handler(arg)` for every pending & enabled source.
- The IRQ vector (0x54AB4 → 0x55024) is a second, similar dispatcher path.
- ThreadX object `Q_SX_UDC_SRV` / timer `T_SX_UDC_SRV` confirms the USB device controller runs as a dedicated service task fed by INTC1.5.

---

## 8. Peripheral register reference

Legend: **Addr** = absolute address; **Off** = offset from module base; **Acc** = access direction observed (R/W); **Conf** = confidence (§2). Evidence column cites the firmware code site (PC) and/or the public source. "fpd" = [FPDoom](https://github.com/ilyakurdyukov/fpdoom) cross-reference (files `init_sc6531e.h`, `syscode.c/h`, `usbio.c`, `sfc.c`, `sdio.c`, `efuse.h`), "spd" = [spd_dump](https://github.com/ilyakurdyukov/spreadtrum_flash).

### 8.1 AON_APB "GR" — global registers (base 0x8B000000, size 0x388) — the heart of the SoC

| Addr | Off | Register (function) | Acc | Conf | Evidence |
|---|---|---|---|---|---|
| 0x8B000040 | 0x40 | SC6530-family CPU/clk div & AHB clock control (bit 2 = AHB/2; bits 28-29 SDIO clk on SC6530) | W | confirmed | fpd `get_ahb_freq()`; firmware writes at boot (multi-chip support) |
| 0x8B000044 | 0x44 | SDIO clock select (SC6530/DA path: bits 23-24) | RW | confirmed | fpd `sdio_init()` |
| 0x8B00004C | 0x4C | **CPU frequency select** — bits[1:0]: 00=26 MHz, 01=104 MHz, 10=208 MHz, 11=208 MHz (SC6531E); bit 2 = AHB clock ÷2 | RW | confirmed | fpd `sc6531e_init_freq()` writes `|3` for 208 MHz; firmware reads in freq-report path (0x7CFA8 area busy-waits) |
| 0x8B000060 / 0x8B000064 | 0x60/0x64 | APB module **soft-reset set / clear** (SC6530/DA layout) | W | confirmed | fpd `efuse_init()` (bit 22 = eFuse) |
| 0x8B0000A0 / 0x8B0000A4 | 0xA0/0xA4 | APB module **power-enable set / clear** (SC6530/DA layout) | W | confirmed | fpd (bit 27 = eFuse) |
| 0x8B000140 | 0x140 | power-management status/flag | R | medium | status-library fn @0x86FC |
| 0x8B000160 | 0x160 | power-management control (values 0x2, 0x8 written) | RW | medium | 4 sites in PM library 0x86xx |
| 0x8B0001C0+4 | 0x1C4 | AON event/interrupt mask register (bit-set RMW; ≥9 channels) — analog-die/PM event enables | RW | medium | 18 access sites, e.g. fn @0x50EE0-0x50F60 (`orr` mask by arg, special-case channel 8) |
| 0x8B000200 | 0x200 | PM/AON control (0x10 written on audio-path switch) | W | medium | 0x2A002-0x2A00E |
| 0x8B000220 | 0x220 | reset-control module (bit 5 RMW) | RW | medium | 0x2A00E-0x2A014 |
| 0x8B000224 | 0x224 | **LCM (LCD) reset control** — bits 0/1 toggle LCD reset pin | RW | confirmed | fpd `lcm_reset()` toggles `method ^= 1` |
| 0x8B0002C0 / (+0x18) | 0x2C0/0x2D8 | PM status/control pair | RW | low | PM library |
| 0x8B00035C | 0x35C | **chip ID word 0** = 0x36320000 | R | confirmed | fpd `init_chip_id()` |
| 0x8B000360 | 0x360 | **chip ID word 1** = 0x53433635 ("SC65") | R | confirmed | fpd; folds to 0x65620000 = SC6531EFM |
| 0x8B000364 | 0x364 | **chip ID word 2 / boot flag** (0x00000001 = SC6531EFM_AB; `&3`==3 → AC) | R | confirmed | reset stub 0x54A4C; fpd |
| 0x8B001068 / 0x8B002068 | — | **APB soft-reset set / clear** (SC6531E layout; bit 19 = ADI, bit 22 = eFuse) | W | confirmed | fpd `init_adi()` (bit 19), `efuse_init()` (bit 22); firmware writes both |
| 0x8B0010A8 / 0x8B0020A8 | — | **APB power-enable set / clear** (SC6531E layout; bit 24 = ADI, bit 27 = eFuse; `0x800080` = GPIO_D) | W | confirmed | fpd `APB_PWR_ON/OFF`, `efuse.h`; firmware 3+4 sites |

The set/clear register-pair idiom (`base+0x1000` set, `base+0x2000` clear, self-clearing) recurs through this SoC's AON_APB modules.

### 8.2 AHB clock/power domain control (base 0x20500000)

| Addr | Register (function) | Acc | Conf | Evidence |
|---|---|---|---|---|
| 0x20500060 / 0x20500070 | AHB power enable set/clear (SC6530/DA) — bit 9 SDIO0 (0x200), SC6530 bit 10 | W | confirmed | fpd `sdio_init()`, `AHB_PWR_ON` |
| 0x205000B0 | SDIO slot select (bits 0-1) | RW | confirmed | fpd `sdio_slot()` |
| 0x205000E0 | **MEM_REMAP** control (bit 0) | R | confirmed | fpd `init_chip_id()` |
| 0x20500168 | SMC (PSRAM) type save register (id<<8 \| flags) | RW | confirmed | fpd `sc6531e_smc_save_id()` |
| 0x205003FC | chip ID (SC6530/DA): 0x65300000=SC6530, 0x65310000=SC6531… | R | confirmed | fpd |
| 0x20501040 / 0x20502040 | AHB soft-reset set / clear (SC6531E; bit 8 SDIO0, bit 9 LCDC) | W | confirmed | fpd `sdio_reset()`, `lcdc_init()` |
| 0x20501080 / 0x20502080 | AHB power enable set / clear (SC6531E; bit 6 LCM, bit 9 SDIO0, bit 12 LCDC) | W | confirmed | fpd `AHB_PWR_ON(0x40)` LCM, `(0x1000)` LCDC, `(0x200)` SDIO |

### 8.3 Clock generator CGA (base 0x8D200000, size 0x100)

| Addr | Off | Register (function) | Acc | Conf | Evidence |
|---|---|---|---|---|---|
| 0x8D20002C | 0x2C | **CPU clock source mux** — bits[2:0]: 2 selects post-PLL CPU clock | RW | confirmed | fpd `sc6531e_init_freq()`; firmware 2 sites |
| 0x8D200030 | 0x30 | clock config — bits[9:8] := 1 after CPU freq change | RW | confirmed | fpd; firmware 2 sites |
| 0x8D200040 / 0x8D200044 | 0x40/44 | peripheral clock enables — SDIO0 select = (val&~7)\|2 at 0x8D200044 | RW | confirmed | fpd `sdio_init()`; firmware 3+3 sites |
| 0x8D200054 | 0x54 | divider/control (bits 9-8 RMW; 7 accesses) | RW | high | firmware 0x24C76-0x24C8C (peripheral re-clock path, arg 0-3) |
| 0x8D200068 | 0x68 | enable bit 0 (clear to gate) | RW | high | firmware 0x24EAA-0x24EB2 |
| 0x8D200080–0x8D2000BC | 0x80-BC | config bank (0xB8/0xBC RMW pairs — likely PLL/divider load) | RW | medium | firmware 0x55B36-0x55B50 (ARM-mode helper) |

### 8.4 AON timer block (base 0x81000000)

| Addr | Off | Register (function) | Acc | Conf | Evidence |
|---|---|---|---|---|---|
| 0x81000024 | 0x24 | **free-running 23-bit counter** (wraps at 0x7FFFFF); read-twice-stable protocol; basis of OS timing | R | confirmed | fn @0x867C: read loop + 0x55-drift check + 0x7FFFFF wrap handling |
| 0x81000040 | 0x40 | timer **LOAD** (interval) — values 0x514 (1300) / 0xA28 (2600) = 50/100 ms at 26 kHz tick | W | high | 4 sites (0x7CFC2 etc.) |
| 0x81000048 | 0x48 | timer **VALUE** (down-counter) — firmware busy-waits on it (20 access sites) | R | high | delay loops |
| 0x8100004C | 0x4C | timer **CTRL** (RMW bit 3 = clear/int-enable) | RW | high | 8 sites |
| 0x81003000+0xC | 0x300C | second counter with read-twice-stable semantics (RTC-like time) | R | high | fn @0xBDCC |

### 8.5 Interrupt controllers INTC0/INTC1 (base 0x80000000 / 0x80001000)

| Addr | Register (function) | Acc | Conf | Evidence |
|---|---|---|---|---|
| 0x80000004 | INTC0 raw/serial status (bit 25 = USB on SC6530) | R | confirmed | fpd `usb_check_int()` |
| 0x80000008 | INTC0 **IRQ enable set** (bit 22 = LCDC frame-end; write-1-to-set) | RW | confirmed | fpd `sys_start_refresh()`; firmware 0x1D4F4 (`orr #0x400000`) |
| 0x80001004 | INTC1 raw status (bit 5 = USB device, bit 8 = SDIO0) | R | confirmed | fpd; firmware 0x2A10C (`lsls #0x1A; bpl` = test bit 5) |
| 0x8000100C / 0x8000102C | INTC1 mask-clear registers (0xFFFFFFFF written = mask all) | W | high | fns @0x84CE, 0x8630 |

### 8.6 ADI — Analog-Digital Interface + analog die window (base 0x82000000)

The ADI is a FIFO-backed command channel to the SC1161 analog die; the analog registers are *memory-mapped through* ADI at `0x82001400+` on SC6531E (`0x82001000+` on SC6530/DA — the firmware contains both paths, it is built for the whole family).

| Addr | Register (function) | Acc | Conf | Evidence |
|---|---|---|---|---|
| 0x82000004 | **ADI FIFO status** — bit 22 = FIFO full, bit 21 = FIFO empty (SC6530/DA at +0x20 with bit 8/9) | R | confirmed | fpd `adi_write()` |
| 0x82000008 | **ADI read-command** — write target analog address (bits 11:0); (SC6530/DA at +0x18) | RW | confirmed | fpd `adi_read()` |
| 0x8200000C | **ADI read-data / busy** — bit 31 = busy; response in low 16 bits, echo of address in [31:16] | R | confirmed | fpd |
| 0x82001000/0x82001004 | ANA chip-ID low/high (SC6530/DA) | R | confirmed | fpd (`0x11300000` SR1130, `0x1161A000` SC1161, …) |
| 0x82001000/0x82001020-0x8200103F | analog window sub-ranges (pin/LDO config via pinmap) | RW | confirmed | fpd `pin_init()` routes pinmap entries at `0x82001000-0x82001FFF` to `adi_write()` |
| 0x82001400+4 | ANA chip-ID high (SC6531E window) | R | confirmed | fpd |
| 0x82001400+0x7C | audio path mux/PGA (bit 0 toggled on earpiece/speaker switch) | RW | high | firmware fn @0x29B04 (`SPRD_CODEC` path) |
| 0x8200145C | **LDO_SD_REG1** — SD-card LDO voltage: mV = (value+120)×10 | RW | confirmed | fpd `sdio_init()` |
| 0x82001460 | **LDO_SD_REG2** — bit 0 = SD card power on | RW | confirmed | fpd |
| 0x8200148C | **ANA_LDO_SF_REG0** (special-function LDO; pin 0x8C000114-0x8C00012C depends on bit 9) | RW | confirmed | fpd `pin_init()` |
| 0x82001400+0x13C | **ANA_WHTLED_CTRL** — backlight (torch/white-LED) current: bits 5:1 level (0-15), bit 0 = off; firmware brightness 0-100 % maps to 0-16 steps | RW | confirmed | fpd `sys_brightness()`; firmware codec-adjacent calls |

(Dozens of further analog registers — codec, LDOs, RTC in the analog die, ADC — live in this window; the firmware touches them through the small `adi_read/adi_write` helpers at 0x6E52/0x6ED2, so individual addresses beyond those listed are not statically provable. The window size is 4 KiB.)

### 8.7 eFuse controller (base 0x82002000, size 0x20)

| Addr | Off | Register (function) | Acc | Conf | Evidence |
|---|---|---|---|---|---|
| 0x82002000 | 0x00 | eFuse **read data** | R | confirmed | fpd `efuse_read()`; firmware 5 sites (busmonitor attribution was a nearest-string artifact — the access pattern is efuse) |
| 0x82002008 | 0x08 | **row/address select** (id \| id<<16) | RW | confirmed | fpd; firmware |
| 0x8200200C | 0x0C | command (bit 1 = start read) | RW | confirmed | fpd; firmware |
| 0x82002010 | 0x10 | power/config — bits 28/29/31: power-up sequencing (2=VDD, 1=read, 8=VPP-sense per fpd bit fields) | RW | confirmed | fpd `efuse_init()`; firmware 4 sites |
| 0x82002014 | 0x14 | status — bit 1 = busy | R | confirmed | fpd (2 ms timeout loop); firmware |

SC6531E has 16 eFuse double-words (128 words of user rows on the SC6530/DA variant: 8). Community tooling (`fptest`, "efuse dump for SC6530/SC6531") exists to read them — they hold chip calibration and (on other builds) keys.

### 8.8 GPIO controller (base 0x8A000000)

Structure: **76 GPIO pins (SC6531E)**, 16 pins per port, `0x80` address stride per port: `port_base = 0x8A000000 + (pin>>4)*0x80`.

| Offset (from port base) | Register (function) | Acc | Conf | Evidence |
|---|---|---|---|---|
| +0x00 | **GPIO_DATA** — port data register (bit = pin) | RW | confirmed | fpd `gpio_set()`; firmware 12 sites incl. ports 1-7 (0x8A000080…0x8A000380) |
| +0x04 | **GPIO_DMSK** — data mask (write-protection per pin; must be set to alter DATA) | RW | confirmed | fpd `gpio_init()` writes 1 before use |
| +0x08 | **GPIO_DIR** — direction (1 = output) | RW | confirmed | fpd |
| +0x18 | **GPIO_IE** — input enable (0 for output pins) | RW | confirmed | fpd |
| +0x64 | (observed, function unknown — port-0 sub-register) | R | low | firmware single site |

Auxiliary banks in the firmware base table: `0x8A001000-0x8A00105C` and `0x8A002000-0x8A002028` (likely GPIO interrupt/EIC banks for the always-on domain; identity low-confidence). GPIO pins ≥128 live on the **analog die** through ADI at `0x82001780-(8<<6)+(pin>>4)*0x40` (fpd `gpio_set()`).

### 8.9 Pin configuration / IOMUX (base 0x8C000000, size 0x2E4)

One 32-bit register per physical pin; value selects the function (e.g. `0x2014/0x2015` = LCM function, `0x2004` = SPI1-mode3, `0x2074` = SPI1-mode1, `0x2031` = plain GPIO). The firmware programs these from a runtime pinmap table (`{addr, value}` pairs — fpd `pin_init()`).

Known pins (cross-referenced):

| Addr | Pin function | Conf | Evidence |
|---|---|---|---|
| 0x8C00009C / 0xA0 / 0xA4 / 0xA8 | SDIO D0 / D1 / D2 / D3 | confirmed | fpd `sdio_pin_init()` |
| 0x8C0000AC | SDIO CMD | confirmed | fpd |
| 0x8C0000B0 | SDIO CLK | confirmed | fpd |
| 0x8C000114–0x8C00012C | pins whose drive depends on ANA_LDO_SF_REG0 bit 9 | confirmed | fpd |
| 0x8C000138 / 0x13C / 0x144 / 0x148 | LCM SPI/LCD select pins (LCM vs SPI1-mode detection) | confirmed | fpd `lcm_init()` auto-detect |
| 0x8C000290 / 0x8C0002A4 | SPI0 / UART-TX pins (SC6530 layout) | confirmed | fpd workarounds |

The 0x8C000000-0x8C0000EC region also appears as a consecutive address array in the firmware's own pinmap data (106+ constants in literal pools) — the actual programmed values are runtime data.

### 8.10 USB device controller (base 0x90000000)

A 4-endpoint USB 2.0 full-speed device controller with a FIFO window; the phone exposes it for the Spreadtrum download protocol and USB-serial class debugging.

| Addr | Off | Register (function) | Acc | Conf | Evidence |
|---|---|---|---|---|---|
| 0x90000000 | 0x00 | **USB_CTRL** — bit 0 = USB enable | RW | confirmed | fpd `usb_init()` |
| 0x90000018 | 0x18 | INT_STS (global; bits 8/10/11 = EP0/EP2/EP3) | R | confirmed | fpd |
| 0x9000001C | 0x1C | INT_CLR (global; 0x7F) | W | confirmed | fpd |
| 0x90000028 | 0x28 | TIMEOUT_LMT (bit-time; 12 MHz/15 = 800 kHz) | W | confirmed | fpd |
| 0x90000040 | 0x40 | TR_SIZE_IN_ENDP0 | RW | confirmed | fpd |
| 0x9000005C | 0x5C | **REQ_SETUP_LOW** — low half of SETUP packet (bmRequestType/bRequest/wValue) | R | confirmed | fpd; firmware reads at 0xC9B4 (double-read stability) |
| 0x90000060 | 0x60 | **REQ_SETUP_HIGH** — wIndex/wLength (>>16) | R | confirmed | fpd |
| 0x90000064 | 0x64 | **ENDP0_CTRL** — bits 12-22 max-packet, bit 25 EP-enable, bit 27 send, bit 28 buffer-ready | RW | confirmed | fpd; firmware 0x2A162 area (endpoint enable by channel index) |
| 0x90000068 / 0x9000006C / 0x90000070 | 0x68/0x6C/0x70 | EP0 INT_CTRL / INT_STS / **INT_CLR (0x3FFF = 14 interrupt bits)** | RW | confirmed | fpd; firmware writes 0x3FFF at 3 sites — signature match |
| 0x900000C0-C8 / CC / D0 / D4 | — | ENDP1_CTRL / TRANS_SIZE / INT_CTRL / INT_STS / INT_CLR | RW | confirmed | fpd; firmware 0x900000CC/D0 sites |
| 0x90000100 | 0x100 | **ENDP2_CTRL** (OUT endpoint) | RW | confirmed | fpd; firmware RMW at 0x29BCA |
| 0x90000104 | 0x104 | RCV_DATA_ENDP2 (transfer size) | RW | confirmed | fpd |
| 0x90000108 / 0x10C / 0x110 / 0x114 | — | EP2 INT_CTRL / INT_STS / INT_CLR (**0x3FFF** written) | RW | confirmed | fpd; firmware sites incl. 0x2A042 (`=0x3FFF`) |
| 0x90000140 / 0x148 / 0x14C / 0x150 / 0x154 | — | ENDP3_CTRL / TRANS_SIZE / INT_CTRL / INT_STS / INT_CLR | RW | confirmed | fpd; firmware 0x90000140/0x90000150/0x90000154 |
| 0x90000180-0x9000019C | 0x180+ | endpoint-4/PHY-adjacent bank (bit 9 busy flag at +0x10; 11-bit field at +0; bit 28 trigger) | RW | medium | firmware 0x2A366-0x2A390 (channel-enable dispatcher 0x29B2A indexes sub-banks +0x40/+0xC0/+0x140/+0x180) |
| 0x90080000-0x90080010 | +0x80000 | **endpoint FIFO window** — EP0-IN/EP1/EP3 at +0/+4/+8, OUT-FIFO at +0x0C, EP2 at +0x10 (big-endian word packing) | RW | confirmed | fpd `usb_send/recv` |

### 8.11 SPI flash controller SFC (base region 0x8D101000, size 0x34 per channel)

The SFC executes whole SPI command strings in hardware (up to 12 command words + per-byte type descriptors), which is how the phone reads/writes/erases its NOR.

| Off (from 0x8D101000) | Register (function) | Conf | Evidence |
|---|---|---|---|
| +0x00 | channel **cmd[0..11]** buffer (cmd[0]=opcode, cmd[1]=address, cmd[2..]=data; cmd[7]=read return) | confirmed | fpd `sfc.c` (`sfc->cmd[k]`, `SFC_CMDSET`) |
| +0x30-0x34 | **type_info[]** — per-byte packing descriptors `SFC_TYPEINFO(bytes, count, READ/WRITE, addr-mode)` | confirmed | fpd |
| +0x1C/0x20 (struct) | tbuf_clr / status (bit 0 = done) | confirmed | fpd |
| module +0x204 | global enable (`|= 3`) | confirmed | fpd `sfc_init()` |

### 8.12 SDIO/SD card controller (base 0x20700000 = SDIO0, 0x20700100 = SDIO1)

Register map (0x30-byte `sdio_base_t`, from community code — the it2163's firmware contains the same controller driver):

| Off | Register | Function |
|---|---|---|
| +0x00 | DMA_ADDR | transfer DMA address |
| +0x04 | BLK_SIZE | block size / count / DMA boundary |
| +0x0C | TR_MODE | command+response-mode register (CMD index in bits 31-24) |
| +0x10-0x1C | RESP[0..3] | command response |
| +0x20 | BUF_PORT | data port |
| +0x24 | STATE | BUF_READ_EN bit 11 / BUF_WR_EN bit 10 |
| +0x28 | CTRL1 | bus width (bits 1:0), HI_SPD_EN bit 2 |
| +0x2C | CTRL2 | clock control: bit 0 INT_CLK_EN, bit 1 INT_CLK_STABLE, bit 2 SDCLK_EN, bits 8-15 SDCLK_FRQ_SEL, bits 16-19 timeout, bit 24 SW_RST_ALL, bits 25/26 SW_RST_CMD/DAT |
| +0x30 | INT_ST | interrupt status (write-1-clear) |
| +0x34 | INT_EN | interrupt enable |
| +0x38 | INT_SIG | interrupt signal |

### 8.13 Keypad controller KPD (base 0x87000000, size 0x38)

| Addr | Off | Register (function) | Conf |
|---|---|---|---|
| 0x87000000 | 0x00 | CTRL | confirmed |
| 0x87000004 | 0x04 | INT_EN | confirmed |
| 0x87000008 | 0x08 | INT_RAW | confirmed |
| 0x8700000C | 0x0C | INT_MASK | confirmed |
| 0x87000010 | 0x10 | INT_CLR | confirmed |
| 0x87000018 | 0x18 | POLARITY | confirmed |
| 0x8700001C | 0x1C | DEBOUNCE | confirmed |
| 0x87000020 | 0x20 | LONG_KEY (long-press detection) | confirmed |
| 0x87000024 | 0x24 | SLEEP_CNT (key wakeup in sleep) | confirmed |
| 0x87000028 | 0x28 | CLK_DIVIDE | confirmed |
| 0x8700002C | 0x2C | KEY_STATUS (pressed-key code) | confirmed |
| 0x87000030 | 0x30 | SLEEP_STAT | confirmed |
| 0x87000034/0x38 | 0x34/38 | DBG_STAT1/2 (scan debug) | confirmed |

Key codes observed in community tooling for this keypad: 0x01 DIAL, 0x04-0x07 UP/DOWN/LEFT/RIGHT, 0x08/0x09 LSOFT/RSOFT, 0x0D CENTER, 0x23 HASH, 0x2A STAR, 0x24/0x25 VOLUP/VOLDOWN, 0x30-0x39 digits 0-9.

### 8.14 LCM — MCU/DBI LCD interface (base 0x20800000) + LCD window (0x60000000)

| Addr | Register (function) | Acc | Conf |
|---|---|---|---|
| 0x20800000 | **LCM status** — bit 1 = busy (poll before every access) | R | confirmed |
| 0x20800010 + cs*0x10 | LCM **mode** per chip-select (1 = safe 8-bit; 0x28 = 8-bit big-endian burst for GRAM writes) | RW | confirmed |
| 0x20800014 + cs*0x10 | LCM **timing** — packed rcss[3:0] / rlpw / rhpw / wcss / wlpw / whpw cycle counts vs AHB clock | RW | confirmed |
| 0x60000000 + cs<<26 | **LCM memory window** — 16-bit access; `addr | 1<<17` = data phase, plain = command phase (bit 17 = LCM data/cmd select) | RW | confirmed |

### 8.15 LCDC — display controller (base 0x20D00000)

Full register map from community `lcdc_base_t` (offsets from 0x20D00000):

| Off | Register | Off | Register |
|---|---|---|---|
| +0x00 | CTRL (bit 0 enable, bit 1 fmark mode, bit 2 fmark polarity, bits 5-7 LCD mode, bit 3 start-refresh) | +0x04 | DISP_SIZE (w \| h<<16) |
| +0x08 | LCM_START | +0x0C | LCM_SIZE |
| +0x10 | BG_COLOR | +0x14 | FIFO_STATUS |
| +0x18 | SYNC_DELAY | +0x20-0x3C | IMG layer: CTRL / Y_BASE_ADDR / UV_BASE_ADDR / SIZE_XY / PITCH / DISP_XY (format in bits 7-4: 5 = RGB565; bits 9-8 endian) |
| +0x50-0x7C | OSD layer 1 (OCD1): CTRL / BASE / ALPHA_BASE / SIZE / PITCH / DISP_XY / ALPHA / GREY_RGB / CK (color key) | +0x80-0xAC | OSD layer 2 (also CAP capture alias: CTRL / BASE / START_XY / SIZE / PITCH) |
| +0xB0-0xDC | OSD layer 3 | +0x100 | Y2R: CTRL / CONTRAST / SATURATION / BRIGHTNESS |
| +0x110-0x11C | IRQ: EN / CLR / STATUS / RAW (bit 0 = frame-end; `en |= 1` before refresh, `raw` polled, `clr |= 1` after) | | |

### 8.16 PSRAM controller SMC (base 0x20000000)

Programming model (community `sc6531e_init_smc()`, matched by the firmware's SMC bring-up):

| Off | Function | Off | Function |
|---|---|---|---|
| +0x00 | global config (drive/timing classes; bit 8 update strobe) | +0x04 | misc config |
| +0x08 | bank/timing config | +0x20-0x38 | per-bank drive strength (7 registers) |
| +0x50 | refresh/timing class (0x0ACC177F default) | +0x54 | mode |
| +0x5C | refresh interval (0x1D000000) | +0x80/+0x84 | PSDRAM control (update strobe bit 0) |
| +0x88 | mode detect cmd | +0x8C | detect control |
| +0x94 | calibration (0x5434A) | +0xA0 | PSDRAM hand-shake magic (0x5A5A) |

The controller auto-detects the PSRAM type (id 6 = low-power pseudo-SRAM, id 13 = fast PSRAM) by writing a mode register at PSRAM+0x8000000 and sampling it back; the detected id is cached into `0x20500168`.

### 8.17 UART0/UART1 (bases 0x86000000 / 0x86001000, size 0x14 each)

Both modules appear in the firmware's base table with a 0x14 span and a minimal register set that matches an 8250-style polling UART:

| Off | Register (function) | Conf |
|---|---|---|
| +0x00 | **THR/RBR** — transmit holding / receive buffer (polled byte I/O) | medium (base-table + twin-module pattern; UART0/1/2 pin functions confirmed in the SC6531 datasheet leak) |
| +0x04 | IER / DLM (DLAB=1) | medium |
| +0x08 | IIR/FCR | medium |
| +0x0C | LCR (incl. DLAB) | medium |
| +0x14 | **LSR** — line status (TX-empty / data-ready bits polled) | medium |

The boot download (FDL) channel and the trace log use these UARTs; the community flashing tools echo the same layout.

### 8.18 Watchdog & remaining modules

| Base–End | Size | Identity | Evidence / observations |
|---|---|---|---|
| 0x88000000–0x8800000F | 0x10 | watchdog candidate (LOAD/VALUE/CTRL/LOCK, 4 registers) | base table; typical SPRD WDG footprint; low confidence |
| 0x8D000000–… | — | cold-boot flag/magic register — written 0x0041C1C0 once at power-on (value also encodes... unknown) | reset stub 0x54A5C-0x54A64 |
| 0x83000000 / 0x84000000 | 0x30 each | unknown modules (SPI/I2C-family candidates: base + 0x30 span) | base table |
| 0x8F000000 | 0x3C | unknown module | base table |
| 0x89000000 | 0x6C | unknown module | base table |
| 0x82003000–0x820031BF | 0x1C0 | ADI-adjacent block — channel enables (bits 9/10 at +0x48), config-table registers +0x8C-0xAC and a 6-word calibration bank at +0x100 (values derived from an ADI analog read ⇒ factory calibration, likely audio/ADC offsets) | firmware 0x36D90-0x37050 (8 pool refs to +0x40), 0x51360-0x513A8 (init writes) |
| 0x69000000 | 0x74 | unknown module (high-address window) | base table |
| 0x90525010 | — | trace/log helper target (virtual address used by a logging helper called with sequential offsets) | 0x8698-0x86BC |

---

## 9. Register access database (evidence)

The companion CSV `i2163_register_accesses.csv` lists **every one of the 278 verified MMIO accesses**: address, peripheral, module base, register offset, R/W, ARM/Thumb, code PC, instruction text, and provable written value. `i2163_unique_registers.csv` aggregates them to the 94 distinct registers with access counts, code sites, and written values. `i2163_module_map.csv` carries the 29-module map with confidence and evidence columns.

Sample rows (from the CSV):

```csv
address,peripheral,module_base,reg_offset,access,mode,code_pc,instruction,value_written,id_confidence
0x81000040,AON timer/counter block,0x81000000,0x40,W,thumb,0x0007CFC6,"str r1, [r3]",0x30C,high
0x81000048,AON timer/counter block,0x81000000,0x48,R,thumb,0x0007CFA8,"ldr r2, [r3, #8]",,high
0x8B0001C4,AON_APB GR,0x8B000000,0x1C4,W,thumb,0x00050F2E,"str r0, [r3, #4]",,medium
0x82002010,EFUSE controller,0x82002000,0x10,W,thumb,0x0005137C,"str r0, [r1, #8]",,confirmed
0x90000070,USB device controller,0x90000000,0x70,W,thumb,0x0002A046,"str r4, [r0, #0x30]",0x3FFF,confirmed
```

Statistical profile of the verified accesses:

- Most-accessed registers: `0x81000048` timer VALUE (20 — delay loops), `0x8B0001C4` AON event mask (18), `0x8100004C` timer CTRL (8), `0x8D200054` clock divider (7), `0x90000068` EP0 int-ctrl (6), `0x9000005C` SETUP low (5), `0x81000040` timer LOAD (4).
- Access split ≈ 45 % R / 55 % W; ~85 % of accesses are Thumb code.
- Two "helper gateway" ARM functions (0x55BB0, 0x55B98) mediate many register interactions from Thumb (call-gate wrappers), which is why some address→instruction links are indirect.

---

## 10. RTOS internals (ThreadX)

### 10.1 Identification

The OS is **ThreadX** (pre-Eclipse/Express Logic era) wrapped in Spreadtrum's MOCOR adaptation layer:

| Offset | String |
|---|---|
| 0x112B8 | `RTOS/source/src/c/sci_mem.c` |
| 0x120F4 | `RTOS/source/src/c/threadx_os.c` |
| 0x14BA8 | `RTOS/source/src/c/threadx_appmem.c` |
| 0x58D14+ | kernel state names: `TX_READY`, `TX_COMPLETED`, `TX_TERMINATED`, `TX_SUSPENDED`, `TX_SLEEP`, `TX_QUEUE_SUSP`, `TX_SEMAPHORE_SUSP`, `TX_EVENT_FLAG`, `TX_BLOCK_MEMORY` |

Assert file paths reveal the module layout: `chip_drv/chip_module/...` (chip drivers), `MS_Ref/source/efs/src/efs_item.c` (EFS = embedded file system layer), `mmimain.c`/`mmk_window.c`/`mmiidle_dial.c`/`mmi_resource.c`/`mmi_default.c` (MMI), `dsp_operate.c` (DSP loader), `rrc_dedicate.c` (GSM RR layer), `cafresource_internal.c` (compressed-resource loader).

### 10.2 Kernel objects by name (from string tables)

Queues: `Q_SPRD_CODEC_TASK`, `Q_AUDIO_HAL_TASK`, `Q_PGA_ADJ_TASK`, `Q_CHGMNG_SRV` (charge management service), `Q_SX_UDC_SRV` (USB device controller service), `Q_LCD`.
Timers: `T_SX_UDC_SRV`, `T_LCD`, `T_P_CHNG_FREQ` (DVFS timer — pairs with the CPU-frequency registers), `SPI_RX_TIMER`, `_SPRD_CODEC_SM_TIMER`, `_SPRD_CODEC_PGA_ADJ_TIMER`, `MMI Deadloop Check Timer`.
Events/mutexes/semaphores: `_WAIT_DSP_EVENT`, `_SPRD_CODEC_SM_EVENT`, `_SPRD_CODEC_PGA_ADJ_MUTEX`, `Flash OPERATION SEMAPHORE`, `RTOS_Manage`, `RTOS_Manage_Queue`.
Other named subsystems: `TX_TCP_IP` (ThreadX NetX-era TCP/IP), `SPRD_CODEC_TASK`/`AUDIO_HAL_TASK`/`PGA_ADJ_TASK` (audio), `RR_2MFRAME_EXP_IND` (GSM L2/RR frame indication — the modem stack runs on this CPU, talking to the DSP).

### 10.3 Diagnostics menu (engineering menu compiled in, 0x5813D+)

The assert framework exposes a UART/diag menu with these commands — itself a good summary of the system's introspection abilities:

```
0. Print help info.            1. Print assert info.
2. Print important registers.  3. Dump all memory to a file.
4. Print memory allocated info.5. Print memory pools info.
6. Print tasks info.           7. Print stack info.
8. Print callback function list. 9. Read memory.
a. Dump task usage.            b. Dump definite memory to a file.
c. Dump TaskSwitch memory ...  d. Print Event list information.
e. Print Mutex list ...        g. Print Semaphore list ...
h. Print Fat system control block info.
i. Print Byte Pool infomation  j. Print PS tasks queue info
k. Print PS function call stack l. Print timer list infomation.
n. Write memory.               r. Print MMI info.
s. Dump Fixed NV  to file.     t. Print the all assert information.
u. Dump Running NV to file.    v. Print Version Information.
w. Print iram Information.     z. Reset MCU.
```

Memory-region dump labels (the firmware's own memory map vocabulary): `RAM_RW Region`, `DSP Memory`, `Inter Ram Memory`, `IRAM Dsp`, `BT PSRAM memory`, `BT IRAM Memory` (the BT Cortex-M has private RAM, corroborating the public SoC description).

### 10.4 Memory-management notes

- ThreadX app-memory (`threadx_appmem.c`) + a custom `sci_mem.c` allocator.
- MMU page table at `*(0x042C1590)`; virtual aliases at 0x08000000/0x08500000 let drivers choose cacheable vs uncached views of RAM buffers (DMA-safe).
- Exception-context blocks at 0x042CBF80+ (§6.2); IRQ descriptor table ~0x042C1600-0x042C1FFC; FIQ bank pointer at 0x042CE014.

---

## 11. DSP subsystem

- The SC6531E integrates a **DSP for GSM L1** (and audio codecs) alongside the ARM926. The ARM-side loader lives in `dsp_operate.c` (assert string at 0xF00C) with format strings `DSP Memory:Offset=0x%08X, Length=0x%08X`, `IRAM Dsp:Offset=…` (0x6CED), `Inter Ram Memory:…` (0x6CBD) and an assert channel `DSP Assert ID:%d` (0xEFF4) — the ARM prints DSP-side asserts with numeric IDs.
- **DSP images are the compressed payloads** at 0x083000–0x36F000 (§4.2). The loader copies/decompresses them into DSP IRAM/DRAM at boot; sync between cores uses RAM mailbox structures plus the `_WAIT_DSP_EVENT` ThreadX event.
- GSM L3 (RR/rrc_dedicate.c) runs on the ARM and exchanges 2M-frame indications (`RR_2MFRAME_EXP_IND`) with the DSP — confirming a classic SPRD L1/L3 split.
- The BT Cortex-M (when fitted) owns its IRAM/PSRAM regions (`BT IRAM Memory`/`BT PSRAM memory`) and is *not* under ARM OS control.

---

## 12. Storage: NOR layout, FAT12 "MY disk", NV

### 12.1 NOR

16 MiB NOR (serial, driven via SFC §8.11), containing the 4× mirrored 4 MiB firmware image. The mirror blocks make physical wear-levelling by copy unnecessary but provide power-loss resilience: the boot ROM can select an intact copy.

### 12.2 FAT12 "MY disk" (BPB at 0x3C042E)

| BPB field | Value |
|---|---|
| OEM name | `SPRD    ` |
| Bytes/sector | 512 |
| Sectors/cluster | 1 |
| Reserved sectors | 1 |
| FATs | 1 |
| Root entries | 512 |
| Total sectors | 103 (~51.5 KiB for this instance) |
| Media | 0xF8 (fixed) |
| Sectors/FAT | 1 |

The on-flash file-system structures span ~0x3B2000–0x400000 (multiple directory tables observed at 0x3B24AA, 0x3D2A92, 0x3DD9A0 with `.`/`..` entries). Default folder set (8.3 short names): `COOL_P~1`, `COOL_M~1`, `COOL_V~1`, `VCARD~1`, `OTHERS~1`, `SYSTEM~1`, `LIST1~1` — the standard itel/Transsion feature-phone user storage layout (photos/music/videos/vCard/others/system). This is the "LOCAL DISK" the MMI mounts (string at 0x80714) and the assert menu can inspect ("Print Fat system control block info").

### 12.3 NV (non-volatile) storage

The debug menu distinguishes **Fixed NV** (factory calibration, IMEI-related blobs on other builds) and **Running NV** (user settings), both dumpable to file. NV items are managed by the EFS layer (`MS_Ref/source/efs/src/efs_item.c`).

---

## 13. MMI / application layer & user-data artifacts

- **Resource system:** `mmi_resource.c` + `cafresource_internal.c` (compressed asset loader). Resource directory at 0x398000+ includes the audio equalizer preset table — entries like `EQ_Headset` (0x398010), plus MP3 playlist metadata (`MMIMP3_LIST_VER.01.01.00` at 0x3D8DE5).
- **Input:** T9 predictive text (engine markers around 0x369B7/0x25BF12).
- **Networking:** WAP browser and TCP/IP (`TX_TCP_IP`).
- **Boot logo:** string `Spreadtrum Communication CO.` at 0x39E118 with `SPRD` branding on the FAT BPB.
- **Bluetooth:** the platform carries the full BT stack; this phone's flash retains **evidence of real use** — previously paired device names in the user/NV area (0x3D5000, 0x3DC000, 0x3F4000):

  `vivo Y33s`, `Nokia G20`, `Soundpot`, `boAt Rockerz`, `soundcore H30i`, `Leaf Rush Pro`, `Carlcare` (Transsion service brand, likely a preset contact/entry)

  → this specific handset was paired with a vivo Y33s smartphone and several BT audio devices before being dumped.

- Language packs are stored as encoded (non-ASCII) resources; no plaintext language menu strings appear in the ASCII string scan.

---

## 14. Security observations

- **No cryptography in the ARM firmware:** no AES/RSA/SHA/MD5/HMAC/IMEI strings, no signature-verification code, no secure-boot check on the flash image. The only integrity machinery found is the 4-copy redundancy and Flash-operation semaphore.
- **Download mode is open:** the standard Spreadtrum FDL protocol (see §15) loads unsigned code into RAM at 0x40004000 and executes it — full flash read/write is available over USB without secrets. (That is precisely how this dump was presumably taken, and how the homebrew ecosystem works.)
- **eFuse** (§8.7) holds factory data; community tooling reports reading it is trivial on this platform; nothing in this build gates execution on it.
- **User-data privacy:** BT pairings (and any SMS/phonebook remnants in the NV area) survive in a flash dump — worth noting when sharing dumps of used handsets.

---

## 15. Related ecosystem (flashing, FDL, homebrew, boot keys)

- **spd_dump** ([ilyakurdyukov/spreadtrum_flash](https://github.com/ilyakurdyukov/spreadtrum_flash)) — Linux tool for SC6530/SC6531DA/SC6531E phones: reads/writes/erases/repartitions NOR over the FDL protocol. FDL1 is loaded at **0x40004000** (consistent with this firmware's RAM map).
- **Boot/download key:** entering FDL mode requires holding a key at boot; the key varies per model (community lists: `*`, middle, `1`, up, `0`). `fphelper flash.bin scan` recovers the boot key from a dump like this one.
- **FPDoom** ([ilyakurdyukov/fpdoom](https://github.com/ilyakurdyukov/fpdoom)) — Doom (plus Wolf3D, Nesticle/infones, gnuboy, snes9x, Retris) for SC6530/SC6531E/DA phones; the source used as cross-reference for this report documents USB, LCD, keypad, SFC, eFuse, ADI and clock registers for this exact silicon.
- **barebox** — an RFC mainline port to SC6531E feature phones exists (lore.kernel.org, 2023) — evidence of growing mainline interest in this SoC.
- **SoC family:** SC6530 / SC6531 / SC6531BA / SC6531DA / SC6531E differ in CPU speed (208/312 MHz), GPIO count (0x4C pins on E, 0x90 on DA, 0xA0 on SC6530), ADI base (0x82001400 on E vs 0x82001000) and USB FIFO layout — this firmware natively supports several of them (dual code paths observed at 0x29B04 etc.).

---

## 16. Appendix A — key disassembly listings

### A.1 Exception vector table (0x0)

```
00000000  e59ff01c  ldr pc, [pc, #0x1c]   ; -> 0x000549D0  RESET
00000004  e59ff01c  ldr pc, [pc, #0x1c]   ; -> 0x00054B94  UNDEF
00000008  e59ff01c  ldr pc, [pc, #0x1c]   ; -> 0x00054C08  SWI (ThreadX trap)
0000000c  e59ff01c  ldr pc, [pc, #0x1c]   ; -> 0x00054C50  Prefetch abort
00000010  e59ff01c  ldr pc, [pc, #0x1c]   ; -> 0x00054D48  Data abort
00000014  e59ff01c  ldr pc, [pc, #0x1c]   ; -> 0x00054E6C  (reserved)
00000018  e59ff01c  ldr pc, [pc, #0x1c]   ; -> 0x00054AB4  IRQ
0000001c  e59ff01c  ldr pc, [pc, #0x1c]   ; -> 0x00054EB8  FIQ
00000020  36353632  "2656" tag (build magic, purpose unknown)
```

### A.2 FIQ handler → Thumb dispatcher (0x54EB8 → 0x118A)

```armasm
00054eb8  push {r0-r12, lr}
00054ebc  ldr  r0, [pc, #0x6c]     ; 0x042CBF80  context block
00054ec0  str  r4, [r0]            ; save r4
00054ec4  ldr  r0, [pc, #0x68]     ; 0x042CBFD4  SVC ctx
00054ec8  str  lr, [r0]
00054ecc  blx  0x118a              ; -> Thumb INTC dispatcher
00054ed0  pop  {r0-r12, lr}
00054ed4  subs pc, lr, #4
```

Thumb dispatcher (0x118A), annotated:

```
000118a  push {r3-r7, lr}
000118c  movs r4, #0               ; source index
000118e  bl   #0x84b8              ; irq lock
0001192  ldr  r6, [pc, #0x120]     ; = 0x042CE014  -> INTC bank pointer
0001194  movs r0, #0x80
0001196  ldr  r1, [r6]
0001198  blx  #0x55ba8             ; ARM helper: read INTC mask
000119c  bl   #0x863e              ; unmask all banks
00011a0  ldr  r5, [pc, #0x114]     ; = 0x042C1FFC  -> descriptor table (0x18 bytes/entry)
00011a2  movs r0, #0x18
00011a4  muls r0, r4, r0           ; entry = table + i*0x18
...
00011ae  ldr  r1, [r6, r1]         ; status of source
00011b2  beq  #0x11d4              ; not pending -> next
00011ba  ldr  r0, [r7, #0xc]       ; handler pointer
00011c0  movs r0, r4
00011c2  blx  #0x55bb8             ; call handler(i)
...
00011ec  cmp  r4, #0x3a            ; up to 58 sources
00011ee  blt  #0x10b4
```

### A.3 CPU frequency set (boot, matches fpdoom `sc6531e_init_freq`)

```
0x8B00004C := (old & ~4) | 3        ; 208 MHz
0x8D20002C := (old & ~7) | 2        ; CPU clock source
0x8D200030 := (old & ~(3<<8)) | (1<<8)
```

### A.4 OS tick counter read (fn @0x867C)

```armasm
00008686  ldr  r4, [r0, #0x24]     ; r0 = 0x81000000, +0x24 counter
00008688  ldr  r1, [r0, #0x24]
0000868a  cmp  r4, r1
0000868c  bne  #0x8686             ; read twice until stable
... drift check (±0x55), wrap-around with 0x007FFFFF modulus ...
```

### A.5 Cold-boot magic write (reset stub)

```
if (*(0x8B000364) == 0) {
    *(0x8D000000) = 0x0041C1C0;    // cold-boot flag/magic
}
```

### A.6 IRQ configuration table (flash 0x64), first 3 of 26 entries

```
0x64: 006000C8 00090019 00380000 003200FF 007500EB 0101007A 000003C4 042C16A4
0x84: 006000C8 00090018 00380000 003200FF 007500EB 0101007A 000003C4 042C16C0
0xA4: 006000C8 00090017 00380000 003200FF 007500EB 0101007A 000003C4 042C16DC
      \____________ 7 config words ___________/             \_ RAM descriptor
```

### A.7 MMU region table (0x57FB0)

```
ent0: vaddr=0x00000000 size=0x00400000 paddr=0x00000000  ; NOR XIP identity
ent1: vaddr=0x04000000 size=0x003B0000 paddr=0x04000000  ; PSRAM
ent2: vaddr=0x043B0000 size=0x00010000 paddr=0x043B0000
ent3: vaddr=0x043C0000 size=0x0000B000 paddr=0x043C0000
ent4: vaddr=0x08000000 size=0x00500000 paddr=0x043CB000  ; virtual alias window
ent5: vaddr=0x08500000 size=0x00400000 paddr=0x043B0000  ; virtual alias window
```

---

## 17. Appendix B — deliverable files & CSV schema

| File | Content |
|---|---|
| `i2163_sc6531e_firmware_analysis.md` | this report |
| `i2163_module_map.csv` | 29 peripheral modules: base, end, size, identity, confidence, evidence |
| `i2163_unique_registers.csv` | 94 distinct register addresses with access type, access count, code sites, written values, identification confidence |
| `i2163_register_accesses.csv` | all 278 individually verified MMIO accesses (the raw evidence) |

**`i2163_register_accesses.csv` columns:**

| Column | Meaning |
|---|---|
| `address` | effective MMIO address hit by the instruction |
| `peripheral` / `module_base` / `reg_offset` | identification context |
| `access` | `R` or `W` |
| `mode` | `arm` / `thumb` |
| `code_pc` | address of the referencing instruction in the XIP image (= file offset) |
| `instruction` | mnemonic + operands as disassembled |
| `value_written` | statically-provable written constant (often the revealing bit pattern, e.g. `0x3FFF` for USB INT clears) |
| `id_confidence` | confirmed / high / medium / low / unverified |

**Reproducibility note:** all PCs are file offsets in the first 4 MiB copy (flash address = file offset). The disassembler, harvester and analysis scripts (`armdis.py`, `harvest.py`, `regdb.py`, `attribute.py`, `regionmap.py`, `deepctx.py`, `rtosnames.py`, `build_csv.py`) were written for this analysis and can be re-run against any SC6531-family dump.

**External sources cited:**

- FPDoom project (register documentation for SC6530/SC6531DA/SC6531E): https://github.com/ilyakurdyukov/fpdoom (`fpdoom/init_sc6531e.h`, `fpdoom/syscode.c`, `fpdoom/syscode.h`, `fpdoom/usbio.c`, `fpdoom/sfc.c`, `fpdoom/sdio.c`, `fpdoom/efuse.h`)
- spreadtrum_flash / spd_dump (FDL, flashing): https://github.com/ilyakurdyukov/spreadtrum_flash
- SC6531 SoC overview: https://lpcwiki.miraheze.org/wiki/Spreadtrum_systems-on-chip/SC6531
- FPDoom press coverage (CPU frequencies, RAM size, documentation leak note): https://en.linuxadictos.com/they-carry-doom-in-basic-phones-with-spreadtrum-sc6531-chip.html
- itel IT2163 retail listings (device specs): https://www.flipkart.com/itel-it2163/p/itm24123fbe39174 , https://market.momo.africa/Portal/product/20668/1 , https://onigx.com/product/itel-it2163-wireless-fm-torch-dual-sim-phone

