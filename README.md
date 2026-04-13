# MAFP8800 Fingerprint Driver for Linux

An open-source [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) driver for the **Microarray MAFP8800** SPI fingerprint sensor, found in devices like the GPD MicroPC 2. The driver is fully functional: enrollment, verification, and PAM integration all work reliably.

The installable driver lives in a [libfprint fork](https://github.com/IngeniousIdiocy/libfprint-mafp) (branch `mafp-driver`). This repository contains the standalone driver source and detailed documentation for anyone who wants to understand how it works.

## Why this exists

The MAFP8800 has **zero official Linux support** -- no mainline kernel driver, no libfprint driver, nothing on GitHub.

The only Linux driver that exists is a **closed-source binary** distributed informally on the [GPD Devices Discord](https://discord.com/invite/FzEsh3k). It ships as a pre-compiled `libfprint-2.so` (no source code) packaged for Ubuntu 24.10 only.

**This is a security problem.** A fingerprint driver has privileged access to biometric data and runs as root. Distributing it as an unverifiable binary through Discord -- with no code review, no reproducible build, no signature -- means users must blindly trust that the binary is what it claims to be.

This project provides a **fully open-source replacement** where every line of code is visible and auditable.

## Status

| Feature | Status |
|---------|--------|
| Sensor detection and identification | Working |
| Hardware calibration (gain, thresholds) | Working |
| Calibration persistence | Working |
| Finger detection with hysteresis | Working |
| Image capture (160x37 px, 16-bit) | Working |
| Image enhancement | Working |
| Enrollment (8 stages via fprintd) | Working |
| Fingerprint matching (SIFT-WHT descriptors) | Working |
| PAM integration (sudo, login) | Working |
| Upstream submission to libfprint | Not yet started |

## Supported hardware

| Device | Sensor | Chip ID | Interface | Status |
|--------|--------|---------|-----------|--------|
| GPD MicroPC 2 | Microarray MAFP8800 (FP36) | 0x24 | SPI (ACPI HID `MAFP8800`) | Working |

The community binary also supports a second variant (FP88, chip ID 0x58) with separate `mafp_sensor88_*` functions, suggesting a different image geometry. This driver only supports the FP36 variant. If you have hardware with chip ID 0x58, please open an issue.

## Building and installing

This driver is built as part of a [libfprint fork](https://github.com/IngeniousIdiocy/libfprint-mafp).

### Prerequisites

```bash
sudo apt install -y meson ninja-build libfprint-2-dev libglib2.0-dev \
  libgusb-dev libnss3-dev libgudev-1.0-dev libpixman-1-dev \
  gobject-introspection libgirepository1.0-dev
```

### Build and install

```bash
git clone https://github.com/IngeniousIdiocy/libfprint-mafp.git
cd libfprint-mafp
git checkout mafp-driver
meson setup builddir -Ddoc=false -Dgtk-examples=false
ninja -C builddir
sudo ninja -C builddir install
sudo ldconfig
```

### System configuration

**Udev rule** -- auto-bind spidev to the sensor on boot:

```bash
sudo tee /etc/udev/rules.d/70-mafp-spidev.rules << 'EOF'
ACTION=="add|change", SUBSYSTEM=="spi", ENV{MODALIAS}=="acpi:MAFP8800:", \
  RUN{builtin}+="kmod load spi:spidev", \
  RUN+="/bin/sh -c 'echo spidev > %S%p/driver_override && echo %k > %S%p/subsystem/drivers/spidev/bind'"
ACTION=="add", KERNEL=="spidev*", SUBSYSTEM=="spidev", MODE="0660", GROUP="plugdev"
EOF
sudo udevadm control --reload-rules
```

**spidev buffer size** -- the sensor needs 20 KB transfers:

```bash
echo 'options spidev bufsiz=32768' | sudo tee /etc/modprobe.d/spidev-bufsiz.conf
```

### Testing

```bash
sudo systemctl restart fprintd
fprintd-list $USER                          # Should show "Microarray MAFP Fingerprint Sensor"
sudo fprintd-enroll -f right-index-finger   # Enroll (8 touches)
sudo fprintd-verify                         # Verify
```

### Enable PAM (fingerprint for sudo/login)

```bash
sudo pam-auth-update --enable fprintd
```

---

## How the driver works

### Architecture

The driver is a single C file (`mafp8800.c`) that subclasses `FpDevice` directly (not `FpImageDevice`). All SPI operations run in a dedicated worker thread, with the main GLib thread dispatching enroll/verify/identify requests via GCond/GMutex signaling.

**Why not FpImageDevice?** libfprint's `FpImageDevice` base class runs NBIS minutiae extraction (mindtct + bozorth3) on captured images. NBIS requires ~500 DPI images with clear ridge/valley patterns. The MAFP8800's 36x160 pixel sensor at ~200 DPI doesn't produce enough detail for reliable NBIS minutiae detection. Instead, the driver implements its own matching algorithm (described below).

### SPI protocol

The sensor uses a register-level SPI protocol (match-on-host mode). All communication is via 4-byte full-duplex SPI transfers:

- **TX:** `[register, value, 0x00, 0x00]`
- **Response:** byte at position 2 of the RX buffer

| Register | Purpose | Values |
|----------|---------|--------|
| 0x00 | Status | Read: 0x41 = ready |
| 0x04 | Chip ID | 0x24 = FP36 |
| 0x0E | Manufacturer | 0x4D = 'M' (Microarray) |
| 0x8C | Reset trigger | Write 0xFF to reset |
| 0x88 | Capture mode | Write 0xFF to enter |
| 0x10-0x5C | Configuration | Gain, timing, thresholds |
| 0x84 | Detection arm | Write 0x00 to arm |

### Image capture pipeline

1. **Reset:** write reg 0x8C = 0xFF, poll reg 0x04 until == 0x24
2. **Configure:** write capture mode registers (0x20, 0x18, 0x38, 0x40, 0x48, 0x3C, 0x44)
3. **Flush:** SPI read 0x26 bytes with cmd 0x78
4. **Read image:** SPI transfer 20480 bytes with cmd 0x70
5. **Parse:** scan for row markers `[0x00, 0x00, 0x0A, 0x5X]`, extract 74-byte rows
6. **Decode:** 37 big-endian 16-bit pixels per row, 160 rows

### Image enhancement

Raw images are enhanced before feature extraction:
1. **Background subtraction** -- a reference frame captured with no finger is subtracted
2. **Min-max normalization** -- pixel values are scaled to use the full 16-bit range

---

## Matching algorithm

The driver uses a binary descriptor matching algorithm reverse-engineered from the community binary's EPVM (Embedded Pattern-Vector Matching) implementation. The algorithm was designed for low-resolution sensors where standard minutiae-based matching fails.

### Pipeline overview

```
Gaussian pyramid (5 levels) --> DoG (4 layers) --> Keypoint detection (maxima + minima)
    --> Orientation assignment --> SIFT-WHT descriptors --> Template storage
    --> Hamming matching --> RANSAC geometric verification --> Score
```

### Gaussian pyramid

Five levels: the original enhanced image plus four progressive Gaussian blurs using fixed-point u16 kernels:

| Level | Kernel | Effective sigma |
|-------|--------|----------------|
| 0 | Original | 0 |
| 1 | 7-tap | ~1.0 |
| 2 | 9-tap | ~2.0 |
| 3 | 13-tap | ~4.0 |
| 4 | 17-tap | ~8.0 |

Four DoG (Difference of Gaussian) layers are computed as adjacent level differences.

### Keypoint detection

Scale-space extrema are detected in a 3x3x3 neighborhood across DoG layers 1-2 (with layers 0 and 3 providing the scale-space neighbors). Both **maxima** (bright features) and **minima** (dark features) are detected -- this is critical for getting enough keypoints on the tiny sensor.

- Maxima: `val > 0` and strictly greater than all 26 neighbors
- Minima: `val < 0` and strictly less than all 26 neighbors
- Up to 100 keypoints total, sorted by response strength

This was verified by disassembling the community binary's `epvm88_extract` function:
- At address `0x1f2ed`: `test %ax,%ax; jle 0x1f590` -- positive values enter the maxima path
- At `0x1f590`: minima path with inverted comparison (`jg` instead of `jl`)

### Orientation assignment

Each keypoint gets a dominant gradient orientation from a 36-bin histogram (10 degrees per bin) computed from the pyramid level corresponding to the keypoint's DoG layer. The histogram is smoothed with a `[0.25, 0.5, 0.25]` kernel and the peak is interpolated.

### SIFT-WHT descriptors

Each keypoint produces a 128-bit (16-byte) binary descriptor:

**Phase 1: Gradient histogram**
- Sample a 17x17 grid at 2-pixel spacing, rotated by the keypoint's orientation
- Gaussian-weight each sample (sigma = 10.0, derived from the binary's `epvmExpTableU16` lookup table)
- Trilinear interpolation into a 4x4 spatial x 8 orientation histogram (128 bins)
- Spatial bin width: 5 pixels (from binary's division by 5120 fixed-point units)
- Spatial bin offset: 7.5 pixels (from binary's 0x1E00 center offset)

**Phase 2: Binarization via Walsh-Hadamard Transform**
1. Rearrange histogram to spatial-group-major order
2. Reduce 8 orientation bins to 4: `[keep, sum(1-3), keep, sum(5-7)]`
3. Apply 4-point WHT on the orientation dimension
4. Apply 16-point WHT on the spatial dimension (4 butterfly levels)
5. Bits 0-63: sign of 63 WHT coefficients (skip DC term)
6. Bits 64-127: odd-orientation bins exceeding the median of all 128 histogram values

Key parameters were extracted from binary disassembly:
- Spatial bin division at `0x212bc`: `imul $0x66666667` + `sar $0x2b` = division by 5120
- Spatial offset at `0x2121e`: `lea 0x1e00(%)` = offset of 7680 fixed-point units
- Gaussian table at `0x21298`: `call epvmExpU16` using `epvmExpTableU16` (4096 entries at `0x41040`)

### Template storage

Each enrollment produces 8 template samples (one per enrollment touch). Each sample is 2012 bytes:

```
[4-byte header] [Section 1: DoG maxima] [Section 2: DoG minima]

Section = [4-byte count] [up to 50 keypoints x 20 bytes]
Keypoint = [16-byte descriptor] [row: u8] [col: u8] [orientation: u16]
```

### Matching

1. **Descriptor matching:** Hamming distance between 128-bit descriptors via XOR + popcount
   - Ratio test: `best * 256 < second_best * 219` (ratio ~0.855)
   - Maximum Hamming distance: 48 bits
   - Up to 15 matches per section, bidirectional deduplication

2. **Geometric verification:** Exhaustive pairwise RANSAC
   - For each pair of correspondences, solve a 2D similarity transform
   - Count inliers within 3.0 pixel distance (9.0 squared)
   - Hard cap of 10 inliers
   - Refit transform from inlier set for better accuracy

3. **Scoring:**
   - 8+ inliers = auto-match (score 10000)
   - 4-7 inliers = score of `inliers * 1250`
   - < 4 inliers = no match
   - Match threshold: score >= 3000

---

## Project history

This driver was built through multi-session reverse engineering of the Windows `MafpWinbioDriver.dll` and the community Linux binary.

1. **Protocol discovery** -- decoded the Spi2spi/Syno protocol from the Windows driver (turned out to be unused by the FP36 chip variant, which uses simple register-level SPI)
2. **First light** -- captured the first raw fingerprint image by matching the community binary's exact register write sequences
3. **Calibration** -- reverse-engineered the binary-search gain optimization and 3-pass detection threshold calibration
4. **Image enhancement** -- implemented background subtraction and normalization matching the community binary
5. **NCC matching** -- initial matching via normalized cross-correlation (worked but had a 67% false-accept rate)
6. **Scale-space keypoints** -- replaced NCC with DoG keypoint detection, SIFT-WHT descriptors, and geometric verification (right structure, but true-accept rate was only 33%)
7. **Descriptor stability** -- four targeted fixes from binary disassembly (DoG minima detection, spatial bin width 8->5px, Gaussian sigma 8->10, gradient source) resolved the remaining matching reliability issues

## License

LGPL-2.1-or-later (matching libfprint's license).

The driver code is original work based on protocol analysis. No proprietary code was copied from the community binary or the Windows driver.
