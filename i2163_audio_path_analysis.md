# itel it2163 / SC6531E + SC1161 Audio Hardware Initialization & PCM Playback Path (Rev. 2)

Reverse-engineering of the first 4 MiB copy of `flash.bin` (XIP image, ARMv5TE Thumb),
cross-validated against the official *SC6531E and SC6531M Device Specification* (989 pp).

**Rev. 2 changelog** — this revision corrects numerous errors found in the first analysis
after cross-referencing the official datasheet:

| # | was (wrong) | now (correct) | evidence |
|---|---|---|---|
| 1 | 0x82003000 called "AUDIO APB peripheral" | **VBC — Voice Band Controller** | DS §6.7, APB map §5.2.2 |
| 2 | 0x8200304C-0x82003074 called "TX FIFO data slots 0-10" | **DAALCCTL0-10 — DAC ALC coefficient registers** | DS Table 7-6 |
| 3 | 0x82003044 called "TX enable/volume" | **DADGCTL — DAC digital gain control** | DS §6.7.5.2.15 |
| 4 | 0x82003048 called "TX control (bit9=DMA, bit10=IRQ)" | **DAHPCTL — DAC IIR HPF control (bit10=Vbhp_en, bit9=Hp_reg_clr)** | DS §6.7.5.2.16 |
| 5 | 0x8200308C-0x820030AC called "IIS rate dividers" | **DANCH_PT* — DAC notch tone point sine/cos/gain parameters** | DS §6.7.5.2.33+ |
| 6 | 0x82003100+ called "channel valid/DMA descriptors" | **HPCOEF0-20 — DAC IIR high-pass filter coefficients** | DS Table 7-6 |
| 7 | 0x83000000 called "DSP mailbox" | **UART0** | DS §5.2.2 APB map |
| 8 | 0x84000000 called "second DSP-ish block" | **UART1** (shared with DSP) | DS §5.2.2 APB map |
| 9 | 0x86000000/0x86001000 called "UART0/UART1" | **I2C0 / I2C1** | DS §5.2.2 APB map |
| 10 | 0x88000000 called "AHB clock-gating register bank" | **PWM** per datasheet (firmware uses 0x88000000+dev*0x20 for module clock/power — unresolved discrepancy) | DS §5.2.2 vs. firmware |
| 11 | 0x820014E0 called "SC1161 module power mux" (LDO/VCM/VBG) | **SLP_LDO_PD_CTRL0 — deep-sleep LDO power-down control** | DS §13.1.1.57 |
| 12 | 0x82001544 called "PA bias mux" | **VIBR_CTRL — vibrator control** | DS §13.1.1.82 |
| 13 | "LDO table at 0x5D140 enables the analog audio LDO / VCM / VBG bias" | **The table configures which LDOs power DOWN during deep sleep — nothing to do with audio bring-up** | DS §13.1.1.57 |
| 14 | 0x8D101000 called "SFC (SPI NOR)" | **GEA / undocumented APB peripheral** (SFC is at 0x20A00000 on AHB per DS §5.6) | DS §5.6.5.1 |
| 15 | 0x8F000000 and 0x8F100000 not identified | **IIS0 and IIS1** (IIS/PCM serial audio interfaces, shared with DSP) | DS §5.2.2, §6.4 |
| 16 | 0x8A002000 and 0x8A003000 not identified | **AUD** (audio digital registers) and **AUDIFD** (audio interface digital) | DS §5.2.2, ch.11 |
| 17 | "PCM samples go into 0x8200304C+ FIFO slots" | **PCM samples go into VBDA0 (0x82003000) / VBDA1 (0x82003004) — the VBC ping-pong DAC data buffers** | DS §6.7.5.2.1 |
| 18 | Missing: ARM-vs-DSP control bit for VBC | **GR 0x8B000044 bit7 (arm_vb_acc) must be set to 1 for ARM control of VBC** | DS §6.7.4.2 |
| 19 | 0x20100000 not identified as DMA | **DMA control registers (AHB)** | DS §5.2.1 AHB map |

---

## Methodology

1. **Image-wide BL scan** — linear 2-byte pass over `0x800–0x400000` decoded every Thumb
   BL/BLX-immediate call site (14 523 total). Direct callers of `ADI_Read (0x6E52)` =
   231 sites; `ADI_Write (0x6ED2)` = 201 sites.

2. **Symbolic forward emulator** (`scripts/audio_emu.py`) — AST-based abstract interpreter
   with literal-pool resolution, ARMv5TE-only decoding (32-bit Thumb only for `bl`/`blx`),
   call inlining to depth 6, and event capture for every `ADI_*` / MMIO store.

3. **Datasheet cross-validation** — every address and register name in this revision was
   checked against the official SC6531E/M Device Specification (chapters 5.2, 6.4, 6.7,
   11, 13). Register semantics that the datasheet documents are marked "high" confidence;
   firmware-only identifications are marked "medium"; unknown ones "low".

---

## 1. ADI call-site census

`ADI_Read (0x6E52)` — polls `0x82000004` bit1 (bridge busy), writes `reg & 0x000FFFFF`
to `0x82000008` (read command), polls again, reads `0x8200000C` (data).

`ADI_Write (0x6ED2)` — polls `0x82000004` bit1, writes value directly to the analog
window address via `str r1, [r0]`. **No RMW inside the wrapper** — every RMW in the trace
is done by the caller.

Both functions acquire/release the ADI bridge lock around each transaction.

Call-site distribution (432 total):

| region | R | W | role (corrected) |
|---|---:|---:|---|
| `0xDC24–0xE310` | 40 | 39 | SC1161 codec analog power / PA chain (firmware-only names) |
| `0xA518–0xAC50` | 22 | 22 | codec clock-divider setup (GR 0x8B000268/26C/274) |
| `0x25094–0x257A2` | 22 | 22 | per-register bit set/clear helpers |
| `0x2849A` | 17 | 17 | codec analog config sweep (0x820015xx/0x820014Ex region) |
| `0x29B04–0x2A88X` | 12 | 16 | SPRD_CODEC driver (0x82001048/60/70/6C/40/44, 0x8200140C/7C) |
| `0x35E78–0x360EA` | 13 | 10 | AUDIO_HAL register-set RMW wrappers |
| `0x38678–0x3941C` | 23 | 22 | AUDIO_HAL device driver |
| `0x38E20` | 17 | 17 | AUDIO_HAL full codec register table walk |

---

## 2. The SC1161 Speaker-Amplifier Power-On Sequence

### Phase A — module clocks (digital side, SC6531E GR block)

From firmware periph stubs at 0x256AE/0x257D0/0x25A7E:

| Step | Register | Value | Effect |
|---|---|---|---|
| 1 | `0x8B0010A8` (GR APB clk-en SET) | `1<<28` | enable APB clock to VBC (firmware bit assignment) |
| 2 | `0x8B002068` (GR soft-reset CLR) | `1<<28` | de-assert VBC soft-reset |
| 3 | `0x8B0010A8` | `1<<14` | enable APB clock to PCM module |
| 4 | `0x8B002068` | `1<<14` | de-assert PCM soft-reset |
| 5 | `0x8B0010A8` | `1<<17` | enable APB clock to AUX0 module |
| 6 | `0x8B002068` | `1<<17` | de-assert AUX0 soft-reset |
| 7 | `0x20501080` (AHB clk-en SET) | `1<<0` | enable AHB clock to DMA |
| 8 | `0x20502040` (AHB soft-reset CLR) | `1<<0` | de-assert DMA soft-reset |

**Critical missing step from first analysis** (from DS §6.7.4.2):

| 9 | `0x8B000044` (GR_GEN2) | `1<<7 \| 1<<4 \| 1<<3` | **arm_vb_acc=1 (ARM control of VBC) + vb_da0on/vb_da1on (DAC IIS clocks)** |

Without step 9 the VBC is controlled by the DSP and ARM writes to 0x82003xxx have no effect.

### Phase A2 — analog-die module enable (SC1161, via ADI, from DS §13.1.1.3/4)

| Step | ADI Register | Value | Effect |
|---|---|---|---|
| 10 | `0x82001408` (MODULE_EN0) | `1<<4` \| existing | **AUD_EN** — enable Audio module PCLK in analog die |
| 11 | `0x8200140C` (ARM_CLK_EN0) | `1<<0 \| 1<<1 \| 1<<7` | **CLK_AUD_IF_EN + CLK_AUD_IF_6P5M_EN + CLK_AUD_SCLK_EN** — enable audio interface clocks in analog die |

### ~~Phase B~~ — REMOVED (was "codec analog LDO enable")

The boot-time table at `0x5D140` writes to `0x820014E0` = **SLP_LDO_PD_CTRL0**
(DS §13.1.1.57) — a deep-sleep LDO power-down control register. Setting a bit means
"power this LDO down during deep sleep." The table has **nothing to do with audio
bring-up**; my first analysis misinterpreted it entirely.

Similarly, `0x82001544` = **VIBR_CTRL** (vibrator control), not a "PA bias mux."

The actual analog bias/LDO for the codec is managed by registers in the
0x82001000-0x820013FF range (SC1161 codec analog registers, **not documented in this
datasheet** — they require the separate SC1161/audio-codec datasheet). The firmware-traced
codec analog writes below are the best available evidence.

### Phase C — codec digital unlock + DAC FIFO (function 0x2A784)

| Step | Code PC | ADI reg | Value | Inferred role |
|---:|---:|---|---|---|
| 1 | `0x2A78C` | 0x82001060 | `0xE551` | codec unlock key #1 |
| 2 | `0x2A7B2` | 0x82001048 | `read & ~8` | clear ADC-enable bit |
| 3 | `0x2A7C2` | 0x82001048 | `read \| 1` | set codec digital enable |
| 4 | `0x2A7D2` | 0x82001048 | `read \| 4` | set DAC enable |
| 5 | `0x2A7DA` | 0x82001070 | `0x0001` | IRQ enable |
| 6 | `0x2A7E4` | 0x8200106C | `0xFFFF` | IRQ mask all |
| 7 | `0x2A7F6` | 0x82001044 | `src >> 16` | FIFO low watermark |
| 8 | `0x2A804` | 0x82001040 | `src & 0xFFFF` | FIFO high watermark |
| 9 | `0x2A820` | 0x82001048 | `read \| 2` | DAC ready / start |
| 10 | `0x2A828` | 0x82001060 | `0x1AAE` | codec unlock key #2 (lock) |
| 11 | `0x2A820` | 0x82001048 | `read & ~2` | clear one-shot start |
| 12 | `0x2A7C2` | 0x82001048 | `read \| 8` | final codec enable |

### Phase D — speaker PA enable chain (function 0x38B60 → 0x0DCxx)

This is the sequence that lifts SPK+/SPK- from 0 V to ~2.07 V DC (Class-D BTL):

| Step | Code PC | ADI reg | Value | Role |
|---:|---:|---|---|---|
| 1 | `0x38736` | 0x82001400+0x1C | `read \| 0x800` | Class-D driver bias enable |
| 2 | `0x38736` | 0x82001400+0x28 | `read & ~0x400` | clear PA discharge |
| 3 | `0x0DD0C` | **0x82001354** | `read \| 1` | ADC enable (PA chain prereq) |
| 4 | `0x0DC98` | 0x82001304 | `read & ~0x1F` | clear PA mode bits |
| 5 | `0x0DCAA` | 0x82001304 | `read \| 6` | PA mode = 6 (Class-D BTL) |
| 6 | `0x0DCD6` | 0x82001304 | `read & ~0x20` | clear PA standby |
| 7 | `0x0DCE6` | 0x82001304 | `read \| 0x40` | PA driver enable |
| 8 | `0x0DC34` | **0x82001300** | `read \| 2` | **DAC/mixer enable** (PA input) |
| 9 | `0x0DD66` | 0x82001354 | `read \| 0xFFF` | PA chain final enable (12 stages) |
| 10 | `0x0DC6A` | **0x82001300** | `read \| 1` | **PA bias enable** — SPK+/- lifts here |
| 11 | `0x0DC74` | **0x82001348** | `0xE0` | PA gain = max |

### Phase E — no external PA-enable GPIO

Confirmed: no `0x8A000000+` GPIO write occurs during audio bring-up (the pinmux entries
at 0x5D678 configure IIS data-line GPIOs, not a PA enable). The Class-D amp is enabled
entirely via ADI steps D-9/D-10.

---

## 3. The Digital Audio / PCM Data Path — VBC, not a FIFO

### 3.1 Peripheral identification (corrected)

From the datasheet APB map (§5.2.2) and the firmware's own MMIO table at 0x5CCC0:

| base | datasheet name | firmware extent | role |
|---|---|---|---|
| 0x82003000 | **VBC** (Voice Band Controller) | 0x1C0 bytes | ARM9's digital audio interface: ping-pong DAC/ADC buffers + IIS slave to codec |
| 0x83000000 | **UART0** | 0x30 | UART (NOT audio) |
| 0x84000000 | **UART1** | 0x30 | UART (shared with DSP; NOT audio) |
| 0x8A002000 | **AUD** | 0x28 | audio digital control (SRC, SDM, DAC/ADC path enables) |
| 0x8A003000 | **AUDIFD** | — | audio interface digital |
| 0x8F000000 | **IIS0** | 0x3C | IIS/PCM serial audio controller (shared with DSP) |
| 0x8F100000 | **IIS1** | — | second IIS controller (shared with DSP) |
| 0x82001000–0x820013FF | (SC1161 codec analog) | — | analog die codec registers via ADI |
| 0x82001400 | (Analog Global Reg) | 0x1BC | PMIC global: MODULE_EN0, ARM_CLK_EN0, LDOs, charger, AUDIO_CTRL0/1 |

### 3.2 VBC register map (DS Table 7-6, corrected)

| offset | name | description |
|---|---|---|
| 0x000 | **VBDA0** | **DAC0 data buffer — write 16-bit PCM samples here** |
| 0x004 | **VBDA1** | DAC1 data buffer |
| 0x008 | VBAD0 | ADC0 data buffer (read) |
| 0x00C | VBAD1 | ADC1 data buffer (read) |
| 0x010 | VBBUFFSIZE | buffer size (1–160 words) |
| 0x014 | VBADBUFFDTA | AD buffer control |
| 0x018 | **VBDABUFFDTA** | DA buffer/mode: b15=**VBENABLE** b13=DA0_DMA b10=RAMSW_EN b9=RAMSW_NUMB |
| 0x01C/0x20 | VBADCNT / VBDACNT | buffer counters (RO) |
| 0x034 | VBINTTYPE | interrupt type |
| 0x038 | VBDATASWT | data format on APB bus |
| 0x03C | VBIISSEL | IIS port select for ADC/DAC |
| 0x040 | DAPATHCTL | DAC path control (side-tone mixing) |
| 0x044 | **DADGCTL** | DAC digital gain (b7=enable, b[6:0]=gain; 0x18 = 0 dB, step 0.75 dB) |
| 0x048 | **DAHPCTL** | DAC IIR HPF control (b10=Vbhp_en, b9=Hp_reg_clr, b8=Wid_sel, b[7:0]=R_limit) |
| 0x04C–0x074 | DAALCCTL0–10 | DAC ALC coefficients |
| 0x078/0x07C | STCTL0 / STCTL1 | side-tone control |
| 0x080 | ADPATHCTL | ADC path control |
| 0x084 | ADDGCTL | ADC digital gain |
| 0x088 | DANCHCTL | notch tone control (b7=pt_tone_en, b8=pt_tone_on, …) |
| 0x08C–0x0D4 | DANCH_* | notch tone point/vt sine/cos/gain parameters |
| 0x100–0x150 | HPCOEF0–20 | DAC IIR HPF coefficients (s0, b0_0, a0_0, b1_0, a1_0, b2_0, a2_0, s1, …) |

### 3.3 The PCM data path — definitive (corrected)

The ARM9 writes **16-bit PCM samples** into **VBDA0 (0x82003000)** or **VBDA1 (0x82003004)**.
Each write goes to the next location in a 160-word ping-pong buffer. The VBC then
serializes the data through its IIS slave interface to the audio codec (SC1161 analog
die, which is the IIS master), which drives the DAC → mixer → Class-D PA → speaker.

The function at 0x36F48 that my first analysis called "the PCM FIFO writer" actually
writes **ALC coefficients** (DAALCCTL0-10 at 0x8200304C-0x82003074), not PCM samples.
This was a fundamental misreading of the register map.

**The correct PCM playback procedure** (from DS §6.7.4.5):

1. Set `VBBUFFSIZE (0x82003010)` = buffer size (e.g., 160 words)
2. Set `VBDABUFFDTA (0x82003018)` bit10 (RAMSW_EN) to allow software access to the ping-pong buffer while VBC is disabled
3. Select which ping-pong buffer via bit9 (RAMSW_NUMB: 0 = buffer 0, 1 = buffer 1)
4. Write PCM samples to `VBDA0 (0x82003000)` — each write fills the next location
5. Set `VBDABUFFDTA` bit15 (**VBENABLE**) to start the VBC — it begins sending data
6. On DAC-buffer-empty interrupt, toggle RAMSW_NUMB and write the next block
7. Alternatively set bit13 (VBDA0DMA_EN) for DMA-driven playback

### 3.4 What the firmware actually writes to the VBC

Re-interpreting my event traces with the correct register map:

| firmware function | VBC registers touched | what it does |
|---|---|---|
| 0x36DAC / 0x36DC8 | DAHPCTL (0x82003048) bits 0x400 / 0x200 | **enable/clear the DAC IIR high-pass filter** (Vbhp_en / Hp_reg_clr) |
| 0x36F98 / 0x36FEC | DADGCTL (0x82003044) | **set DAC digital gain** (volume control, 0.75 dB steps) |
| 0x36F48 | DAALCCTL0-10 (0x8200304C-0x82003074) | **load ALC coefficients** from a RAM table (NOT PCM samples) |
| 0x51360 / 0x513EC | DANCHCTL + DANCH_PT* (0x82003088-0x820030AC) | **configure the DAC notch/test tone** for the current sample rate (NOT rate dividers) |
| 0x36DE4 / 0x36E6C / 0x36EA8 | HPCOEF* (0x82003100+) | **load IIR HPF coefficients** |
| 0x36D90 / 0x36F04 | VBC+0x08 area (VBAD0) | ADC data buffer ops |

### 3.5 Can the ARM9 drive the DAC without the DSP?

**Yes** — but two conditions must be met (DS §6.7.5.1):

1. **GR 0x8B000044 bit7 (arm_vb_acc) = 1** — switches VBC control from DSP to ARM
2. **GR 0x8B000044 bits[4:3] (vb_da0on/vb_da1on) = 1** — enables the DAC IIS clocks

Once set, the ARM9 has full access to all VBC registers via APB at 0x82003000, and can
write PCM samples to VBDA0/VBDA1, use the ping-pong buffers with interrupts or DMA,
and control all DAC path parameters (gain, HPF, ALC, side tone).

The IIS0/IIS1 controllers at 0x8F000000/0x8F100000 are **separate** peripherals (for
external IIS devices like BT audio or FM), also shared with the DSP. They are not
required for the internal codec playback path.

**0x83000000 (UART0) and 0x84000000 (UART1) are NOT part of the audio path.**

---

## 4. Deliverables

### 4.1 Audio-path MMIO/ADI write table

[i2163_audio_path_writes.csv](/home/z/my-project/download/i2163_audio_path_writes.csv) —
186 deduplicated events, now with datasheet-corrected register names. Columns:
`Code PC | Function | Target Address | Register Name | Access | Bitmask/Value | Inferred Role | Confidence | Trace Batch`.

### 4.2 Minimal C initialization snippet (corrected)

See [i2163_audio_init.c](/home/z/my-project/download/i2163_audio_init.c) — rewritten with
the correct VBC register map and the ARM-enable (arm_vb_acc) step that was missing from
Rev. 1.

### 4.3 Unresolved items (flagged, not guessed)

| item | why unresolved |
|---|---|
| SC1161 codec analog register names (0x82001000–0x820013FF) | Not documented in the SC6531E datasheet; requires the separate audio-codec datasheet. Names in the CSV are firmware-traced inferences only. |
| Codec unlock keys (0xE551 / 0x1AAE at 0x82001060) | Decoded from real instructions but semantics unknown; may not be required on cold boot. |
| GR module bit assignments (bit28=VBC, bit14=PCM, bit17=AUX0, bit21=?) | The firmware uses these bits consistently, but the datasheet does not document the GR APB clock-enable bit map. Bit28 = VBC is inferred from the "AUDIO" periph stub. |
| 0x88000000 module clock/power bank | Firmware uses 0x88000000+dev*0x20 for module power; datasheet labels the range "PWM." The discrepancy is unresolved. |
| DMA channel base address | Datasheet says DMA = 0x20100000 (AHB); my firmware trace found pool references to 0x88000020. Exact mapping unresolved. |
| GEA at 0x8D010000 vs 0x8D101000 | Datasheet says 0x8D01_0000; firmware uses 0x8D101000. Likely a datasheet typo or chip-revision difference. |
| AON at 0x8D020000 vs 0x8D200000 | Same discrepancy pattern as GEA. |
| Phase D step timing | Paced by `_SPRD_CODEC_SM_TIMER` in stock firmware; constants in the C snippet are RC-time-constant estimates. |
| DADGCTL volume curve | Bits[6:0] = gain, 0x18 = 0 dB per datasheet; exact curve for values >0x18 (amplitude, step 0.75 dB) verified from DS §6.7.5.2.15. |

---

## Datasheet chapters referenced

| chapter | content used |
|---|---|
| 5.2.1 ARM9 AHB Memory Map | DMA=0x20100000, SFC=0x20A00000, General AHB=0x20500000 |
| 5.2.2 ARM9 APB Memory Map | VBC=0x82003000, UART0=0x83000000, UART1=0x84000000, I2C=0x86000000, Keypad=0x87000000, PWM=0x88000000, GPIO=0x8A000000, AUD=0x8A002000, AUDIFD=0x8A003000, GR=0x8B000000, PIN=0x8C000000, GEA=0x8D010000, AON=0x8D020000, SPI0=0x8E000000, IIS0=0x8F000000, IIS1=0x8F100000 |
| 6.4 IIS and PCM interface | IIS controller register map, TXD register |
| 6.7 VBC Interface | Complete VBC register map (Table 7-6), clock domain, ARM-vs-DSP control, buffer operation, data path |
| 11 Audio System | AUD digital data path, clock structure, AUD_TOP_CTRL / AUDIF register maps |
| 13 Analog Register | Analog-die register map at 0x82001400: MODULE_EN0, ARM_CLK_EN0, SOFT_RST0, SLP_LDO_PD_CTRL0, VIBR_CTRL, AUDIO_CTRL0/1 |

## Tools used

| script | purpose |
|---|---|
| `scripts/audio_trace1.py` | image-wide BL scan + ADI call-site census |
| `scripts/audio_trace2.py` | pool-word scan + call-graph context |
| `scripts/audio_emu.py` | symbolic ARM/Thumb forward emulator |
| `scripts/audio_run2.py` | codec / power / VBC / task batch emulation |
| `scripts/build_audio_csv_v2.py` | rebuild CSV with datasheet-corrected names |
| `scripts/pdfx.py` | PyMuPDF datasheet extraction |
