# MAFP8800 Fingerprint Driver for Linux

An open-source [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) driver for the **Microarray MAFP8800** SPI fingerprint sensor, found in devices like the GPD MicroPC 2.

The installable driver lives in a [libfprint fork](https://github.com/IngeniousIdiocy/libfprint-mafp) (branch `mafp-driver`). This repository contains the driver source and documentation.

## Why this exists

The MAFP8800 has no official Linux support. The only Linux driver available is a closed-source binary distributed on the [GPD Devices Discord](https://discord.com/invite/FzEsh3k) -- pre-compiled `libfprint-2.so` binaries with no source code. A fingerprint driver runs as root with access to biometric data; shipping it as an unverifiable binary is a security problem.

This is a fully open-source replacement.

## Supported hardware

| Device | Sensor | Chip ID | Interface | Status |
|--------|--------|---------|-----------|--------|
| GPD MicroPC 2 | Microarray MAFP8800 (FP36) | 0x24 | SPI (ACPI HID `MAFP8800`) | Working |

The community binary also supports a second variant (FP88, chip ID 0x58) with a different image geometry. This driver only supports FP36. PRs for FP88 support are welcome.

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

## Technical overview

### Why FpDevice instead of FpImageDevice

libfprint's `FpImageDevice` base class runs NBIS minutiae extraction (mindtct + bozorth3) on captured images. NBIS needs ~500 DPI images with clear ridge/valley structure. The MAFP8800 produces a 36x160 pixel image at ~200 DPI -- far too low-resolution for reliable minutiae detection. The driver subclasses `FpDevice` directly and implements its own matching.

### SPI protocol

Register-level SPI, match-on-host. All communication is 4-byte full-duplex transfers: `[register, value, 0x00, 0x00]`, response in rx[2].

### Matching algorithm

The matching pipeline was reverse-engineered from the community binary's EPVM (Embedded Pattern-Vector Matching) implementation:

```
Gaussian pyramid (5 levels) -> DoG (4 layers) -> Keypoint detection (maxima + minima)
    -> Orientation assignment -> SIFT-WHT descriptors -> Template storage
    -> Hamming matching -> RANSAC geometric verification -> Score
```

Each keypoint produces a 128-bit binary descriptor from a rotated 17x17 gradient grid, binarized via Walsh-Hadamard Transform. Templates store up to 50 keypoints per polarity section (maxima and minima separately). Matching uses Hamming distance with a ratio test, followed by exhaustive pairwise RANSAC with an angular consistency pre-filter to solve a 2D similarity transform and count geometric inliers.

## License

LGPL-2.1-or-later (matching libfprint's license).

The driver code is original work based on protocol analysis. No proprietary code was copied from the community binary or the Windows driver.
