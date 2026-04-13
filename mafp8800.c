// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Microarray MAFP8800 SPI Fingerprint Sensor Driver (FP36 variant)
 *
 * Copyright (C) 2026 Mark (GPD MicroPC 2 reverse-engineering project)
 *
 * Protocol decoded from the community libfprint driver binary and
 * verified against working hardware. Uses FP36 register-level SPI
 * protocol (match-on-host mode).
 *
 * Architecture: FpDevice subclass with a dedicated worker thread.
 * All SPI operations run in the worker thread. The main GLib thread
 * dispatches enroll/verify/identify requests via GCond signaling.
 */

#define FP_COMPONENT "mafp8800"

#include "drivers_api.h"

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>


/* ─── constants (from community driver binary decode) ────────────── */

/* Image geometry: 160 rows × 37 pixels, 74 bytes/row (2 hdr + 72 pixel) */
#define MAFP_ROWS             160
#define MAFP_COLS             37
#define MAFP_ROW_BYTES        74       /* 0x4A */
#define MAFP_PIXELS           (MAFP_ROWS * MAFP_COLS)  /* 5920 */
#define MAFP_FRAME_BYTES      (320 * MAFP_ROW_BYTES)   /* 0x5C80 = 23680 */
#define MAFP_ENHANCED_COLS    36       /* column 0 stripped */
#define MAFP_ENHANCED_PIXELS  (MAFP_ROWS * MAFP_ENHANCED_COLS)  /* 5760 */

/* SPI */
#define MAFP_SPI_SPEED        4000000
#define MAFP_RAW_READ_SZ      20480    /* 0x5000 */

/* Chip ID */
#define MAFP_CHIPID_FP36      0x24

/* Detection thresholds (from community binary) */
#define MAFP_DETECT_PX_THRESH 320      /* 0x140: per-pixel delta for "changed" */
#define MAFP_DETECT_RAW_LIMIT 178559   /* 0x2B97F: count*100 must exceed this */
#define MAFP_STABLE_SAD_LIMIT 114687   /* 0x1C1FF: sum-of-abs-diffs for "stable" */

/* Enrollment */
#define MAFP_ENROLL_STAGES    8

/* ─── Scale-space keypoint matching constants (from community binary) ── */

/* Gaussian pyramid: 5 levels (original + 4 blurs), 4 DoG layers */
#define MAFP_PYR_LEVELS       5
#define MAFP_DOG_LEVELS       4

/* Template geometry: 2 banks × 50 keypoints × 20 bytes + headers */
#define MAFP_MAX_KP           50     /* max keypoints per bank */
#define MAFP_NUM_BANKS        2
#define MAFP_DESC_BYTES       16     /* 128-bit binary descriptor */
#define MAFP_KP_META          4      /* row(u8) + col(u8) + orientation(u16) */
#define MAFP_KP_SIZE          (MAFP_DESC_BYTES + MAFP_KP_META)  /* 20 */
#define MAFP_BANK_DATA_SZ     (MAFP_MAX_KP * MAFP_KP_SIZE)  /* 1000 */
#define MAFP_BANK_SZ          (4 + MAFP_BANK_DATA_SZ)  /* 1004 */
#define MAFP_TPL_MAGIC        0xEF
#define MAFP_TPL_SAMPLE_SZ    (4 + MAFP_NUM_BANKS * MAFP_BANK_SZ) /* 2012 */

/* Match scoring (thresholds from community binary disassembly) */
#define MAFP_MATCH_THRESH     3000   /* 0xBB8: score >= this = match */
#define MAFP_MIN_MATCH_PTS    4      /* binary: 3 inliers scores below bias, need 4+ */
#define MAFP_HAMMING_THRESH   48     /* max Hamming distance for descriptor match */
#define MAFP_HAMMING_RATIO    219    /* ratio test: best*256 < second*219 (≈0.855) */
#define MAFP_INLIER_DIST_SQ   9.0   /* 2303/256: binary uses Q8, we use pixel coords */
#define MAFP_MAX_INLIERS      10    /* binary hard-caps inliers at 10 */
#define MAFP_MAX_MATCHES      15    /* binary caps matches per section at 15 */
#define MAFP_MAX_KP_TOTAL     100   /* max keypoints across both DoG layers */

/* Template buffer: header + 8 enrollment samples */
#define MAFP_TPL_HDR_SZ       4
#define MAFP_TPL_BUF_SZ       (MAFP_TPL_HDR_SZ + MAFP_ENROLL_STAGES * MAFP_TPL_SAMPLE_SZ)

/* Calibration file */
#define MAFP_CALIB_PATH       "/var/lib/fprint/mafp_calibration"
#define MAFP_CALIB_SZ         0x2E50   /* 11856 bytes */
#define MAFP_CALIB_MAGIC      0x24

/* ─── device struct ──────────────────────────────────────────────── */

struct _FpiDeviceMafp8800
{
  FpDevice parent;

  int spi_fd;

  /* calibration data (loaded from file or computed) */
  guint8  calib[MAFP_CALIB_SZ];

  /* image buffers (each MAFP_FRAME_BYTES = 23680 bytes of u16 in LE) */
  guint8 *bg_frame;          /* background/image_data reference */
  guint8 *cur_frame;         /* current capture */
  guint8 *stab_frame;        /* stability reference */
  guint8 *detect_ref;        /* best-finger reference (hysteresis) */

  /* enhanced output (MAFP_ENHANCED_PIXELS × 2 bytes, u16 LE) */
  guint16 *enhanced;

  /* SPI scratch buffer */
  guint8 *spi_buf;

  /* detection hysteresis state */
  gboolean detect_flag;      /* was finger detected last call */
  gint32   gray_value;       /* saved detection score */

  /* worker thread */
  GThread    *worker;
  GMutex      lock;
  GCond       cond;
  gboolean    exit_flag;
  gboolean    has_work;
  gboolean    canceled;
  void      (*run_func)(struct _FpiDeviceMafp8800 *self);
};

G_DECLARE_FINAL_TYPE (FpiDeviceMafp8800, fpi_device_mafp8800, FPI, DEVICE_MAFP8800, FpDevice)
G_DEFINE_TYPE (FpiDeviceMafp8800, fpi_device_mafp8800, FP_TYPE_DEVICE)

/* ─── SPI transport ──────────────────────────────────────────────── */

/*
 * Register read/write: 4-byte full-duplex SPI.
 * TX: [reg, val, 0x00, 0x00]
 * Response byte: rx[2] (verified against community driver)
 */
static gint
mafp_set_reg (FpiDeviceMafp8800 *self, guint8 reg, guint8 val)
{
  guint8 tx[4] = { reg, val, 0x00, 0x00 };
  guint8 rx[4] = { 0 };
  struct spi_ioc_transfer tr = {
    .tx_buf = (unsigned long) tx, .rx_buf = (unsigned long) rx,
    .len = 4, .speed_hz = MAFP_SPI_SPEED, .bits_per_word = 8,
  };

  if (ioctl (self->spi_fd, SPI_IOC_MESSAGE (1), &tr) < 0)
    return -1;
  return rx[2];
}

static gboolean
mafp_spi_xfer (FpiDeviceMafp8800 *self, guint8 *buf, gsize len)
{
  struct spi_ioc_transfer tr = {
    .tx_buf = (unsigned long) buf, .rx_buf = (unsigned long) buf,
    .len = (guint32) len, .speed_hz = MAFP_SPI_SPEED, .bits_per_word = 8,
  };
  return ioctl (self->spi_fd, SPI_IOC_MESSAGE (1), &tr) >= 0;
}

/* SPI read: send first 2 bytes of buf, receive len bytes back.
 * Matches community mafp_sensor_spi_read_data semantics. */
static gboolean
mafp_spi_read_data (FpiDeviceMafp8800 *self, guint8 *buf, gsize len)
{
  /* The community driver does write(fd, buf, 2) then read(fd, spi_buf, len).
   * With direct ioctl, we do a single full-duplex transfer of the full length. */
  return mafp_spi_xfer (self, buf, len);
}

/* ─── FP36 chip protocol ─────────────────────────────────────────── */

static gboolean
mafp_fp36_reset (FpiDeviceMafp8800 *self)
{
  mafp_set_reg (self, 0x8C, 0xFF);
  for (int i = 0; i < 20; i++)
    {
      g_usleep (1000);
      if (mafp_set_reg (self, 0x04, 0x00) == MAFP_CHIPID_FP36)
        return TRUE;
    }
  fp_warn ("FP36 reset timeout");
  return FALSE;
}

static void
mafp_fp36_capture_mode (FpiDeviceMafp8800 *self, guint8 gain, guint8 integration, guint8 dac)
{
  mafp_set_reg (self, 0x20, 0x8F);
  mafp_set_reg (self, 0x18, gain);
  mafp_set_reg (self, 0x38, 0x02);
  mafp_set_reg (self, 0x40, 0x00);
  mafp_set_reg (self, 0x48, 0x25);
  mafp_set_reg (self, 0x3C, integration);
  mafp_set_reg (self, 0x44, dac);

  /* Flush/sync: read 0x26 bytes with cmd 0x78 */
  guint8 flush[0x26];
  memset (flush, 0x00, sizeof (flush));
  flush[0] = 0x78;
  mafp_spi_read_data (self, flush, 0x26);
}

static int
mafp_fp36_read_image (FpiDeviceMafp8800 *self, guint8 *out_frame)
{
  guint8 *buf = self->spi_buf;
  memset (buf, 0xFF, MAFP_RAW_READ_SZ);
  buf[0] = 0x70;

  if (!mafp_spi_read_data (self, buf, MAFP_RAW_READ_SZ))
    return 0;

  /* Scan for row markers and pack rows into out_frame */
  int rows = 0;
  int i = 0;

  while (i < MAFP_RAW_READ_SZ - 4 && rows < MAFP_ROWS)
    {
      if (buf[i] == 0x00 && buf[i + 1] == 0x00 &&
          buf[i + 2] == 0x0A && (buf[i + 3] & 0xF0) == 0x50)
        {
          int src = i + 4;
          if (src + MAFP_ROW_BYTES > MAFP_RAW_READ_SZ)
            break;
          memcpy (out_frame + rows * MAFP_ROW_BYTES, buf + src, MAFP_ROW_BYTES);
          rows++;
          i = src + MAFP_ROW_BYTES;
        }
      else
        {
          i++;
        }
    }

  /* Byte-swap: big-endian to little-endian u16 in-place */
  for (int j = 0; j < rows * MAFP_ROW_BYTES; j += 2)
    {
      guint8 tmp = out_frame[j];
      out_frame[j] = out_frame[j + 1];
      out_frame[j + 1] = tmp;
    }

  return rows;
}

/* Capture one frame: reset → capture_mode → read_image */
static int
mafp_fp36_capture (FpiDeviceMafp8800 *self, guint8 *frame)
{
  mafp_fp36_reset (self);
  mafp_fp36_capture_mode (self, self->calib[1], 0x02, 0xA1);
  return mafp_fp36_read_image (self, frame);
}

/* Read a u16 pixel from a frame buffer (row-major, LE) */
static inline guint16
frame_pixel (const guint8 *frame, int row, int col)
{
  int off = row * MAFP_ROW_BYTES + col * 2;
  return (guint16) frame[off] | ((guint16) frame[off + 1] << 8);
}

/* ─── detection mode setup ───────────────────────────────────────── */

static void
mafp_fp36_int_ctl_init (FpiDeviceMafp8800 *self)
{
  mafp_set_reg (self, 0x10, 0xBF);
  guint8 flush[0x26];
  memset (flush, 0x00, sizeof (flush));
  flush[0] = 0x78;
  mafp_spi_read_data (self, flush, 0x26);

  mafp_set_reg (self, 0x20, 0x80);
  mafp_set_reg (self, 0x28, 0x00);
  mafp_set_reg (self, 0x38, 0x02);
  mafp_set_reg (self, 0x3C, 0x38);
  mafp_set_reg (self, 0x44, 0x78);
  mafp_set_reg (self, 0x40, 0x08);
  mafp_set_reg (self, 0x48, 0x1E);
  mafp_set_reg (self, 0x4C, 0x88);
  mafp_set_reg (self, 0x50, 0x00);
  mafp_set_reg (self, 0x54, 0x00);
  mafp_set_reg (self, 0x58, 0x00);
  mafp_set_reg (self, 0x5C, 0x00);
}

static void
mafp_fp36_calc_grey (FpiDeviceMafp8800 *self, guint8 int_val,
                     guint8 *g0, guint8 *g1, guint8 *g2)
{
  mafp_set_reg (self, 0x18, int_val);
  mafp_set_reg (self, 0x84, 0x00);
  g_usleep (10000);
  mafp_set_reg (self, 0x88, 0x00);

  for (int i = 0; i < 20; i++)
    {
      g_usleep (1000);
      if (mafp_set_reg (self, 0x04, 0x00) == MAFP_CHIPID_FP36)
        break;
    }

  *g0 = (guint8) mafp_set_reg (self, 0x54, 0x00);
  *g1 = (guint8) mafp_set_reg (self, 0x58, 0x00);
  *g2 = (guint8) mafp_set_reg (self, 0x5C, 0x00);
}

static void
mafp_fp36_detect_mode (FpiDeviceMafp8800 *self)
{
  mafp_fp36_reset (self);
  mafp_set_reg (self, 0x10, 0xBF);

  guint8 flush[0x26];
  memset (flush, 0x00, sizeof (flush));
  flush[0] = 0x78;
  mafp_spi_read_data (self, flush, 0x26);

  mafp_set_reg (self, 0x20, 0x80);
  mafp_set_reg (self, 0x28, 0x00);
  mafp_set_reg (self, 0x38, 0x06);   /* detect scan mode, NOT 0x02 */
  mafp_set_reg (self, 0x3C, 0x38);
  mafp_set_reg (self, 0x44, 0x78);
  mafp_set_reg (self, 0x40, 0x08);
  mafp_set_reg (self, 0x48, 0x1E);
  mafp_set_reg (self, 0x4C, 0x88);
  mafp_set_reg (self, 0x50, 0xFF);
  mafp_set_reg (self, 0x54, self->calib[4]);
  mafp_set_reg (self, 0x58, self->calib[5]);
  mafp_set_reg (self, 0x5C, self->calib[6]);
  mafp_set_reg (self, 0x18, self->calib[2]);
  mafp_set_reg (self, 0x84, 0x00);
}

/* ─── calibration ────────────────────────────────────────────────── */

static guint8
mafp_crc8 (const guint8 *data, gsize len)
{
  guint8 crc = 0;
  for (gsize i = 0; i < len; i++)
    crc ^= data[i];
  return crc;
}

static gboolean
mafp_load_calib (FpiDeviceMafp8800 *self)
{
  FILE *f = fopen (MAFP_CALIB_PATH, "rb");
  if (!f)
    return FALSE;
  gsize n = fread (self->calib, 1, MAFP_CALIB_SZ, f);
  fclose (f);
  if (n < MAFP_CALIB_SZ)
    return FALSE;
  if (self->calib[0] != MAFP_CALIB_MAGIC)
    return FALSE;
  guint8 crc = mafp_crc8 (self->calib, 0x2E4C);
  return self->calib[0x2E4C] == crc;
}

static void
mafp_save_calib (FpiDeviceMafp8800 *self)
{
  self->calib[0] = MAFP_CALIB_MAGIC;
  guint8 crc = mafp_crc8 (self->calib, 0x2E4C);
  self->calib[0x2E4C] = crc;

  g_mkdir_with_parents ("/var/lib/fprint", 0755);
  FILE *f = fopen (MAFP_CALIB_PATH, "wb");
  if (f)
    {
      fwrite (self->calib, 1, MAFP_CALIB_SZ, f);
      fsync (fileno (f));
      fclose (f);
      fp_info ("calibration saved to %s", MAFP_CALIB_PATH);
    }
}

static void
mafp_fp36_calibrate (FpiDeviceMafp8800 *self)
{
  /* Try loading cached calibration */
  if (mafp_load_calib (self))
    {
      fp_info ("loaded cached calibration (gain=%d, detect_int=%d, thresh=%d/%d/%d)",
               self->calib[1], self->calib[2],
               self->calib[4], self->calib[5], self->calib[6]);
      /* Restore background image from calibration data */
      memcpy (self->bg_frame, self->calib + 8,
              MIN ((gsize)(MAFP_CALIB_SZ - 8), (gsize) MAFP_FRAME_BYTES));
      return;
    }

  fp_info ("running live calibration...");

  /* Binary search for optimal capture gain.
   * Community driver reads 0x400 bytes, sums BE u16 pixel pairs.
   * Target: total pixel sum just below 0x4007F (262,271).
   * This means average pixel ~ 512 across ~512 bytes of pixel data. */
  int low = 0, high = 255, mid = 128;

  for (int iter = 0; iter < 8; iter++)
    {
      mid = (low + high) / 2;
      mafp_fp36_reset (self);
      mafp_fp36_capture_mode (self, (guint8) mid, 0x4C, 0x54);

      /* Read exactly 0x400 bytes (matches community driver) */
      guint8 raw[0x400];
      memset (raw, 0xFF, 0x400);
      raw[0] = 0x70;
      mafp_spi_read_data (self, raw, 0x400);

      /* Community driver: parses rows from 0x400 raw bytes, packs them
       * to start of buffer, then sums exactly 0x250 bytes (296 BE u16
       * values = 4 rows × 37 pixels) regardless of rows found.
       * Target 0x4007F across those 148 u16 values → avg ~1772/pixel. */
      long total = 0;
      int nrows = 0;
      int i = 0;
      /* Parse rows and pack to start of buffer (same as community) */
      while (i < 0x400 - 4 && nrows < 8)
        {
          if (raw[i] == 0x00 && raw[i+1] == 0x00 &&
              raw[i+2] == 0x0A && (raw[i+3] & 0xF0) == 0x50)
            {
              int src = i + 4;
              if (src + MAFP_ROW_BYTES > 0x400)
                break;
              memmove (raw + nrows * MAFP_ROW_BYTES, raw + src, MAFP_ROW_BYTES);
              nrows++;
              i = src + MAFP_ROW_BYTES;
            }
          else
            i++;
        }
      /* Sum exactly 0x250 bytes (148 u16 values) from packed data */
      for (int j = 0; j < 0x250; j += 2)
        total += ((guint16) raw[j] << 8) | raw[j + 1];

      fp_dbg ("calibrate gain search: gain=%d total=%ld (target=%d)", mid, total, 0x4007F);

      if (total > 0x4007F)
        high = mid;
      else
        low = mid;
    }

  self->calib[1] = (guint8) mid;
  fp_info ("calibration: gain=%d", mid);

  /* Capture background image with found gain */
  mafp_fp36_capture (self, self->bg_frame);
  memcpy (self->calib + 8, self->bg_frame,
          MIN ((gsize)(MAFP_CALIB_SZ - 8), (gsize) MAFP_FRAME_BYTES));

  /* 3-pass threshold search for detection */
  guint8 g0, g1, g2;
  guint8 final_int = 0;

  /* Coarse: step 16 */
  for (int v = 0; v < 256; v += 16)
    {
      mafp_fp36_reset (self);
      mafp_fp36_int_ctl_init (self);
      mafp_fp36_calc_grey (self, (guint8) v, &g0, &g1, &g2);
      if (g0 > 100 && g1 > 100 && g2 > 100)
        { final_int = (guint8)(v > 15 ? v - 15 : 0); break; }
    }

  /* Fine: step 4 */
  for (int v = final_int; v < final_int + 16; v += 4)
    {
      mafp_fp36_reset (self);
      mafp_fp36_int_ctl_init (self);
      mafp_fp36_calc_grey (self, (guint8) v, &g0, &g1, &g2);
      if (g0 > 100 && g1 > 100 && g2 > 100)
        { final_int = (guint8) v; break; }
    }

  /* Finest: step 1 */
  for (int v = (final_int > 3 ? final_int - 3 : 0); v <= final_int; v++)
    {
      mafp_fp36_reset (self);
      mafp_fp36_int_ctl_init (self);
      mafp_fp36_calc_grey (self, (guint8) v, &g0, &g1, &g2);
      if (g0 > 100 && g1 > 100 && g2 > 100)
        { final_int = (guint8) v; break; }
    }

  self->calib[2] = final_int > 0 ? final_int - 1 : 0;
  self->calib[3] = 0xFF;
  self->calib[4] = g0 > 20 ? g0 - 20 : 0;
  self->calib[5] = g1 > 20 ? g1 - 20 : 0;
  self->calib[6] = g2 > 20 ? g2 - 20 : 0;

  fp_info ("calibration: detect_int=%d thresh=%d/%d/%d",
           self->calib[2], self->calib[4], self->calib[5], self->calib[6]);

  mafp_save_calib (self);
}

/* ─── finger detection (exact community algorithm) ───────────────── */

static gboolean
mafp_fp36_finger_is_detect (FpiDeviceMafp8800 *self)
{
  /* Capture frame */
  mafp_fp36_capture (self, self->cur_frame);

  /* Count pixels where background is darker than current by > MAFP_DETECT_PX_THRESH.
   * Community checks (bg - cur) > threshold, i.e. finger DARKENS the sensor. */
  int changed = 0;
  for (int row = 0; row < MAFP_ROWS; row++)
    for (int col = 1; col < MAFP_COLS; col++)  /* skip column 0 */
      {
        gint32 bg = (gint32) frame_pixel (self->bg_frame, row, col);
        gint32 cur = (gint32) frame_pixel (self->cur_frame, row, col);
        if ((bg - cur) > MAFP_DETECT_PX_THRESH)
          changed++;
      }

  gint32 raw_score = changed * 100;
  gboolean detected = raw_score > MAFP_DETECT_RAW_LIMIT;

  /* Compute percentage for hysteresis */
  gint32 pct = (MAFP_ENHANCED_PIXELS > 0)
    ? (changed * 100) / MAFP_ENHANCED_PIXELS : 0;

  if (!detected)
    {
      self->detect_flag = FALSE;
      return FALSE;
    }

  /* Hysteresis */
  if (!self->detect_flag)
    {
      /* First detection: clear reference, init score */
      memset (self->detect_ref, 0, MAFP_FRAME_BYTES);
      self->gray_value = 0;
    }

  if (self->gray_value < pct)
    {
      /* Finger pressing harder: update reference to track peak */
      memcpy (self->detect_ref, self->cur_frame, MAFP_FRAME_BYTES);
      self->gray_value = pct;
    }

  self->detect_flag = TRUE;
  return TRUE;
}

static gboolean
mafp_fp36_finger_is_stable (FpiDeviceMafp8800 *self)
{
  long sad = 0;
  for (int row = 0; row < MAFP_ROWS; row++)
    for (int col = 1; col < MAFP_COLS; col++)
      {
        gint32 a = (gint32) frame_pixel (self->cur_frame, row, col);
        gint32 b = (gint32) frame_pixel (self->stab_frame, row, col);
        gint32 d = b - a;
        if (d < 0) d = -d;
        sad += d;
      }
  return sad <= MAFP_STABLE_SAD_LIMIT;
}

/* ─── image enhancement ──────────────────────────────────────────── */

/*
 * Enhancement: bg_frame + 10000 - cur_frame
 * bg_frame = no-finger background (from calibration, stable across sessions)
 * cur_frame = current finger-present capture
 * Finger darkens pixels, so bg > cur → positive result = ridge depth.
 */
static void
mafp_fp36_enhance (FpiDeviceMafp8800 *self)
{
  guint16 *out = self->enhanced;
  const guint8 *bg = self->bg_frame;       /* no-finger background */
  const guint8 *finger = self->cur_frame;  /* current capture with finger */

  guint16 px_min = 0xFFFF, px_max = 0;

  /* Background subtract with +10000 offset, skip column 0 */
  for (int row = 0; row < MAFP_ROWS; row++)
    for (int col = 1; col < MAFP_COLS; col++)
      {
        guint16 bg_val = frame_pixel (bg, row, col);
        guint16 fg_val = frame_pixel (finger, row, col);
        guint16 val = (guint16)((bg_val + 10000 - fg_val) & 0xFFFF);
        int idx = row * MAFP_ENHANCED_COLS + (col - 1);
        out[idx] = val;
        if (val < px_min) px_min = val;
        if (val > px_max) px_max = val;
      }

  guint16 range = px_max - px_min;
  if (range <= 50)
    {
      memset (out, 0, MAFP_ENHANCED_PIXELS * sizeof (guint16));
      return;
    }

  /* Normalize to full 16-bit range */
  for (int i = 0; i < MAFP_ENHANCED_PIXELS; i++)
    {
      guint32 val = out[i] - px_min;
      val = (val * 0xFFFF) / range;
      out[i] = (guint16) MIN (val, 0xFFFF);
    }
}

/* ─── Scale-space keypoint matching ──────────────────────────────── */

/* Gaussian kernels (u16 fixed-point, sum≈65536) from community binary */
static const guint16 kern7[]  = {291, 3539, 15862, 26152, 15862, 3539, 291};
static const guint16 kern9[]  = {339, 1951, 6809, 14415, 18508, 14415, 6809, 1951, 339};
static const guint16 kern13[] = {145, 575, 1771, 4248, 7937, 11549, 13086, 11549, 7937, 4248, 1771, 575, 145};
static const guint16 kern17[] = {170, 433, 977, 1942, 3409, 5280, 7217, 8706, 9268, 8706, 7217, 5280, 3409, 1942, 977, 433, 170};

/* ── Gradient computation for SIFT-WHT descriptor ── */

static void
mafp_compute_gradients (const guint16 *img, int rows, int cols,
                        gint32 *mag, guint16 *ori)
{
  memset (mag, 0, rows * cols * sizeof (gint32));
  memset (ori, 0, rows * cols * sizeof (guint16));

  for (int r = 1; r < rows - 1; r++)
    for (int c = 1; c < cols - 1; c++)
      {
        gint32 gx = (gint32) img[r * cols + c + 1] - (gint32) img[r * cols + c - 1];
        gint32 gy = (gint32) img[(r + 1) * cols + c] - (gint32) img[(r - 1) * cols + c];
        mag[r * cols + c] = (gint32) sqrt ((double) (gx * gx + gy * gy));
        gdouble a = atan2 ((double) gy, (double) gx);
        if (a < 0)
          a += 2.0 * G_PI;
        ori[r * cols + c] = (guint16) (a / (2.0 * G_PI) * 65536.0);
      }
}

/* Internal keypoint representation (not serialized) */
typedef struct {
  guint8  row;
  guint8  col;
  guint8  dog_layer;
  guint8  polarity;    /* 0 = DoG maximum, 1 = DoG minimum */
  gint16  response;    /* absolute value of DoG extremum */
  gdouble orientation;
  guint8  desc[MAFP_DESC_BYTES];
} MafpKeypoint;

/* Correspondence for geometric verification */
typedef struct {
  guint8 pr, pc, gr, gc;
} MafpCorr;

/* ── Gaussian blur (separable, fixed-point u16) ── */

static void
mafp_blur_h (const guint16 *src, guint16 *dst,
             const guint16 *kern, int ksize, int rows, int cols)
{
  int half = ksize / 2;

  for (int r = 0; r < rows; r++)
    for (int c = 0; c < cols; c++)
      {
        guint32 sum = 0;
        for (int k = -half; k <= half; k++)
          {
            int cc = CLAMP (c + k, 0, cols - 1);
            sum += (guint32) src[r * cols + cc] * kern[k + half];
          }
        dst[r * cols + c] = (guint16) (sum >> 16);
      }
}

static void
mafp_blur_v (const guint16 *src, guint16 *dst,
             const guint16 *kern, int ksize, int rows, int cols)
{
  int half = ksize / 2;

  for (int r = 0; r < rows; r++)
    for (int c = 0; c < cols; c++)
      {
        guint32 sum = 0;
        for (int k = -half; k <= half; k++)
          {
            int rr = CLAMP (r + k, 0, rows - 1);
            sum += (guint32) src[rr * cols + c] * kern[k + half];
          }
        dst[r * cols + c] = (guint16) (sum >> 16);
      }
}

static void
mafp_gauss_blur (const guint16 *src, guint16 *dst, guint16 *tmp,
                 const guint16 *kern, int ksize, int rows, int cols)
{
  mafp_blur_h (src, tmp, kern, ksize, rows, cols);
  mafp_blur_v (tmp, dst, kern, ksize, rows, cols);
}

/* ── DoG keypoint detection ── */

static int
mafp_detect_keypoints (gint16 **dog, MafpKeypoint *kps)
{
  int W = MAFP_ENHANCED_COLS;
  int count = 0;

  /* Exclude keypoints near edges: the 17×17 descriptor grid needs
   * ±16 pixels of margin. On a 36-wide image, that means col 5-30. */
  int margin_r = 8, margin_c = 5;
  for (int layer = 1; layer <= 2; layer++)
    for (int r = margin_r; r < MAFP_ROWS - margin_r; r++)
      for (int c = margin_c; c < W - margin_c; c++)
        {
          gint16 val = dog[layer][r * W + c];
          if (val == 0)
            continue;

          gboolean is_max = (val > 0), is_min = (val < 0);
          for (int dl = -1; dl <= 1 && (is_max || is_min); dl++)
            for (int dr = -1; dr <= 1 && (is_max || is_min); dr++)
              for (int dc = -1; dc <= 1 && (is_max || is_min); dc++)
                {
                  if (dl == 0 && dr == 0 && dc == 0)
                    continue;
                  gint16 nb = dog[layer + dl][(r + dr) * W + (c + dc)];
                  if (nb >= val) is_max = FALSE;
                  if (nb <= val) is_min = FALSE;
                }

          if ((is_max || is_min) && count < MAFP_MAX_KP_TOTAL)
            {
              kps[count].row       = (guint8) r;
              kps[count].col       = (guint8) c;
              kps[count].dog_layer = (guint8) layer;
              kps[count].polarity  = is_min ? 1 : 0;
              kps[count].response  = is_min ? -val : val;
              count++;
            }
        }

  /* If we hit the cap, keep strongest by sorting on response */
  if (count >= MAFP_MAX_KP_TOTAL)
    {
      for (int i = 0; i < count - 1; i++)
        for (int j = i + 1; j < count; j++)
          if (kps[j].response > kps[i].response)
            { MafpKeypoint tmp = kps[i]; kps[i] = kps[j]; kps[j] = tmp; }
      count = MAFP_MAX_KP_TOTAL;
    }

  return count;
}

/* ── Orientation assignment (36-bin histogram, [0.25,0.5,0.25] smoothing) ── */

static void
mafp_assign_orientations (guint16 **pyr, MafpKeypoint *kps, int count)
{
  int W = MAFP_ENHANCED_COLS;

  for (int ki = 0; ki < count; ki++)
    {
      int r0 = kps[ki].row, c0 = kps[ki].col;
      const guint16 *img = pyr[kps[ki].dog_layer];
      gdouble hist[36] = {0};
      int radius = 4;
      gdouble sigma = radius * 0.5;

      for (int dr = -radius; dr <= radius; dr++)
        {
          int r = r0 + dr;
          if (r < 1 || r >= MAFP_ROWS - 1)
            continue;
          for (int dc = -radius; dc <= radius; dc++)
            {
              int c = c0 + dc;
              if (c < 1 || c >= W - 1)
                continue;
              gdouble gx = (gdouble) img[r * W + c + 1] - (gdouble) img[r * W + c - 1];
              gdouble gy = (gdouble) img[(r + 1) * W + c] - (gdouble) img[(r - 1) * W + c];
              gdouble mag = sqrt (gx * gx + gy * gy);
              gdouble angle = atan2 (gy, gx);
              if (angle < 0)
                angle += 2.0 * G_PI;
              gdouble w = exp (-(dr * dr + dc * dc) / (2.0 * sigma * sigma));
              int bin = (int) (angle / (2.0 * G_PI) * 36.0);
              if (bin >= 36)
                bin = 35;
              hist[bin] += mag * w;
            }
        }

      /* Smooth with [0.25, 0.5, 0.25], 2 passes */
      for (int pass = 0; pass < 2; pass++)
        {
          gdouble tmp[36];
          for (int b = 0; b < 36; b++)
            tmp[b] = hist[(b + 35) % 36] * 0.25
                   + hist[b] * 0.5
                   + hist[(b + 1) % 36] * 0.25;
          memcpy (hist, tmp, sizeof (hist));
        }

      int best_bin = 0;
      gdouble best_val = hist[0];
      for (int b = 1; b < 36; b++)
        if (hist[b] > best_val)
          { best_val = hist[b]; best_bin = b; }

      if (best_val < 48.0)
        {
          kps[ki].orientation = -1.0;
          continue;
        }

      /* Sub-bin parabolic interpolation */
      gdouble lv = hist[(best_bin + 35) % 36];
      gdouble rv = hist[(best_bin + 1) % 36];
      gdouble offset = 0;
      gdouble denom = lv + rv - 2.0 * best_val;
      if (fabs (denom) > 1e-6)
        offset = 0.5 * (lv - rv) / denom;
      kps[ki].orientation = ((best_bin + offset + 0.5) / 36.0) * 2.0 * G_PI;
    }
}

/* ── SIFT-WHT descriptor (from community binary RE) ──
 *
 * Phase 1: Build 4×4 spatial × 8 orientation gradient histogram (128 bins)
 *          from a 17×17 sample grid rotated by keypoint orientation.
 * Phase 2: Bits 0-63  = sign of 64-point Walsh-Hadamard Transform
 *          Bits 64-127 = median threshold of odd-orientation bins
 */

static void
mafp_compute_descriptor (const gint32 *grad_mag, const guint16 *grad_ori,
                         int rows, int cols,
                         int r0, int c0, guint16 kp_ori, guint8 *desc)
{
  gdouble angle = (gdouble) kp_ori / 65536.0 * 2.0 * G_PI;
  gdouble ca = cos (angle), sa = sin (angle);
  gint32 hist[128] = {0};
  gdouble sigma = 10.0;

  /* Phase 1: 17×17 grid, 2-pixel spacing, rotated by orientation */
  for (int gr = -8; gr <= 8; gr++)
    for (int gc = -8; gc <= 8; gc++)
      {
        gdouble rx = gc * 2.0 * ca - gr * 2.0 * sa;
        gdouble ry = gc * 2.0 * sa + gr * 2.0 * ca;
        int sr = r0 + (int) (ry + 0.5);
        int sc = c0 + (int) (rx + 0.5);
        if (sr < 1 || sr >= rows - 1 || sc < 1 || sc >= cols - 1)
          continue;

        gint32 mag = grad_mag[sr * cols + sc];
        if (mag == 0)
          continue;
        guint16 gori = grad_ori[sr * cols + sc];

        gdouble gauss = exp (-(rx * rx + ry * ry) / (2.0 * sigma * sigma));
        gint32 weight = (gint32) (mag * gauss);

        /* Trilinear interpolation into 4×4×8 histogram (matching binary) */
        gdouble sx_f = (rx + 7.5) / 5.0;
        gdouble sy_f = (ry + 7.5) / 5.0;
        guint16 rel = gori - kp_ori;
        gdouble o_f = (gdouble) rel / 8192.0;

        int sx0 = (int) floor (sx_f), sy0 = (int) floor (sy_f);
        int o0 = (int) floor (o_f);
        gdouble fx = sx_f - sx0, fy = sy_f - sy0, fo = o_f - o0;

        for (int si = 0; si <= 1; si++)
          for (int sj = 0; sj <= 1; sj++)
            for (int oi = 0; oi <= 1; oi++)
              {
                int bx = sx0 + si, by = sy0 + sj, bo = (o0 + oi) & 7;
                if (bx < 0 || bx > 3 || by < 0 || by > 3)
                  continue;
                gdouble w = weight;
                w *= si ? fx : (1.0 - fx);
                w *= sj ? fy : (1.0 - fy);
                w *= oi ? fo : (1.0 - fo);
                hist[bo * 16 + by * 4 + bx] += (gint32) w;
              }
      }

  /* Phase 2a: Rearrange to spatial-group-major */
  gint32 work[128];
  for (int sy = 0; sy < 4; sy++)
    for (int sx = 0; sx < 4; sx++)
      for (int o = 0; o < 8; o++)
        work[sy * 32 + sx * 8 + o] = hist[o * 16 + sy * 4 + sx];

  /* Phase 2b: Reduce orientations 8→4 */
  gint32 wht[64];
  for (int sp = 0; sp < 16; sp++)
    {
      int b = sp * 8;
      wht[sp * 4 + 0] = work[b + 0];
      wht[sp * 4 + 1] = work[b + 1] + work[b + 2] + work[b + 3];
      wht[sp * 4 + 2] = work[b + 4];
      wht[sp * 4 + 3] = work[b + 5] + work[b + 6] + work[b + 7];
    }

  /* Phase 2c: 4-point WHT on orientation */
  for (int sp = 0; sp < 16; sp++)
    {
      gint32 *p = &wht[sp * 4];
      gint32 a = p[0] + p[1], b = p[0] - p[1];
      gint32 c = p[2] + p[3], d = p[2] - p[3];
      p[0] = a + c;  p[1] = a - c;  p[2] = b - d;  p[3] = b + d;
    }

  /* Phase 2d-g: 16-point spatial WHT (4 butterfly levels) */
  for (int stride = 4; stride <= 32; stride <<= 1)
    for (int i = 0; i < 64; i += stride * 2)
      for (int j = 0; j < stride; j++)
        {
          gint32 a = wht[i + j], b = wht[i + j + stride];
          wht[i + j] = a + b;
          wht[i + j + stride] = a - b;
        }

  /* Phase 2h: Bits 0-63 = sign of WHT coefficients (skip DC) */
  memset (desc, 0, MAFP_DESC_BYTES);
  for (int i = 1; i < 64; i++)
    if (wht[i] > 0)
      desc[i / 8] |= (guint8) (1 << (i % 8));

  /* Phase 2i: Bits 64-127 = median threshold of odd orientation bins */
  gint32 sorted[128];
  memcpy (sorted, work, sizeof (sorted));
  for (int i = 1; i < 128; i++)
    {
      gint32 key = sorted[i];
      int j = i - 1;
      while (j >= 0 && sorted[j] > key)
        { sorted[j + 1] = sorted[j]; j--; }
      sorted[j + 1] = key;
    }
  gint32 median = sorted[64];

  for (int i = 0; i < 64; i++)
    if (work[2 * i + 1] > median)
      desc[8 + i / 8] |= (guint8) (1 << (i % 8));
}

/* ── Feature extraction: enhanced u16 image → 2012-byte template ── */

static int
mafp_extract_features (const guint16 *enhanced, guint8 *tpl)
{
  int R = MAFP_ROWS, C = MAFP_ENHANCED_COLS, N = MAFP_ENHANCED_PIXELS;

  /* Allocate pyramid and DoG on heap */
  guint16 *pyr[MAFP_PYR_LEVELS];
  gint16  *dog[MAFP_DOG_LEVELS];
  guint16 *tmp = g_new (guint16, N);
  for (int l = 0; l < MAFP_PYR_LEVELS; l++)
    pyr[l] = g_new (guint16, N);
  for (int l = 0; l < MAFP_DOG_LEVELS; l++)
    dog[l] = g_new (gint16, N);

  /* Build pyramid */
  memcpy (pyr[0], enhanced, N * sizeof (guint16));
  mafp_gauss_blur (pyr[0], pyr[1], tmp, kern7,  7,  R, C);
  mafp_gauss_blur (pyr[1], pyr[2], tmp, kern9,  9,  R, C);
  mafp_gauss_blur (pyr[2], pyr[3], tmp, kern13, 13, R, C);
  mafp_gauss_blur (pyr[3], pyr[4], tmp, kern17, 17, R, C);
  g_free (tmp);

  /* DoG = adjacent level difference */
  for (int l = 0; l < MAFP_DOG_LEVELS; l++)
    for (int i = 0; i < N; i++)
      dog[l][i] = (gint16) pyr[l][i] - (gint16) pyr[l + 1][i];

  /* Detect keypoints */
  MafpKeypoint kps[MAFP_MAX_KP_TOTAL];
  int n_kps = mafp_detect_keypoints (dog, kps);

  /* Assign orientations */
  mafp_assign_orientations (pyr, kps, n_kps);

  /* Compute gradient magnitude and orientation from original image */
  gint32  *grad_mag = g_new0 (gint32, N);
  guint16 *grad_ori = g_new0 (guint16, N);
  mafp_compute_gradients (pyr[1], R, C, grad_mag, grad_ori);

  /* Compute SIFT-WHT descriptors from gradient fields */
  for (int i = 0; i < n_kps; i++)
    {
      if (kps[i].orientation < 0)
        continue;
      guint16 ori16 = (guint16) (kps[i].orientation / (2.0 * G_PI) * 65536.0);
      mafp_compute_descriptor (grad_mag, grad_ori, R, C,
                               kps[i].row, kps[i].col,
                               ori16, kps[i].desc);
    }
  g_free (grad_mag);
  g_free (grad_ori);

  /* Serialize: [4-byte magic/pad] [bank0: 4+1000] [bank1: 4+1000] */
  memset (tpl, 0, MAFP_TPL_SAMPLE_SZ);
  tpl[0] = MAFP_TPL_MAGIC;

  for (int bank = 0; bank < MAFP_NUM_BANKS; bank++)
    {
      int target_polarity = bank;  /* bank 0 = maxima, bank 1 = minima */
      gint32 bcount = 0;
      guint8 *bdata = tpl + 4 + bank * MAFP_BANK_SZ;
      guint8 *kpdata = bdata + 4;

      for (int i = 0; i < n_kps && bcount < MAFP_MAX_KP; i++)
        {
          if (kps[i].polarity != target_polarity || kps[i].orientation < 0)
            continue;
          guint8 *p = kpdata + bcount * MAFP_KP_SIZE;
          memcpy (p, kps[i].desc, MAFP_DESC_BYTES);
          p[16] = kps[i].row;
          p[17] = kps[i].col;
          guint16 ori16 = (guint16) (kps[i].orientation / (2.0 * G_PI) * 65536.0);
          memcpy (p + 18, &ori16, 2);
          bcount++;
        }
      memcpy (bdata, &bcount, sizeof (gint32));
    }

  /* Cleanup */
  for (int l = 0; l < MAFP_PYR_LEVELS; l++)
    g_free (pyr[l]);
  for (int l = 0; l < MAFP_DOG_LEVELS; l++)
    g_free (dog[l]);

  gint32 b0, b1;
  memcpy (&b0, tpl + 4, 4);
  memcpy (&b1, tpl + 4 + MAFP_BANK_SZ, 4);
  fp_info ("extract: %d keypoints (%d + %d)", b0 + b1, b0, b1);
  return b0 + b1;
}

/* ── Hamming distance between two 128-bit descriptors ── */

static inline int
mafp_hamming (const guint8 *a, const guint8 *b)
{
  const guint64 *a64 = (const guint64 *) a;
  const guint64 *b64 = (const guint64 *) b;
  return __builtin_popcountll (a64[0] ^ b64[0])
       + __builtin_popcountll (a64[1] ^ b64[1]);
}

/* ── Geometric verification ── */

static gboolean
mafp_solve_similarity (const MafpCorr *c,
                       gdouble *a, gdouble *b, gdouble *tx, gdouble *ty)
{
  gdouble px1 = c[0].pc, py1 = c[0].pr;
  gdouble gx1 = c[0].gc, gy1 = c[0].gr;
  gdouble px2 = c[1].pc, py2 = c[1].pr;
  gdouble gx2 = c[1].gc, gy2 = c[1].gr;

  gdouble dxp = px2 - px1, dyp = py2 - py1;
  gdouble dxg = gx2 - gx1, dyg = gy2 - gy1;
  gdouble den = dxp * dxp + dyp * dyp;
  if (den < 1.0)
    return FALSE;

  *a  = (dxp * dxg + dyp * dyg) / den;
  *b  = (dxp * dyg - dyp * dxg) / den;
  *tx = gx1 - (*a * px1 - *b * py1);
  *ty = gy1 - (*b * px1 + *a * py1);
  return fabs (*a) <= 4.0 && fabs (*b) <= 4.0;
}

static int
mafp_count_inliers (const MafpCorr *corrs, int n,
                    gdouble a, gdouble b, gdouble tx, gdouble ty,
                    MafpCorr *inlier_out, gdouble *avg_dist)
{
  int count = 0;
  gdouble total = 0;

  for (int i = 0; i < n && count < MAFP_MAX_INLIERS; i++)
    {
      gdouble ex = a * corrs[i].pc - b * corrs[i].pr + tx - corrs[i].gc;
      gdouble ey = b * corrs[i].pc + a * corrs[i].pr + ty - corrs[i].gr;
      gdouble dsq = ex * ex + ey * ey;
      if (dsq <= MAFP_INLIER_DIST_SQ)
        {
          if (inlier_out)
            inlier_out[count] = corrs[i];
          total += dsq;
          count++;
        }
    }

  if (avg_dist)
    *avg_dist = count > 0 ? total / count : 0;
  return count;
}

/* ── Scoring (from community binary disassembly) ── */

/*
 * Binary's scoring: 8+ inliers = auto-match (score 10000).
 * <3 inliers = no match (score 0).
 * 3-7 inliers: score proportional to count. The binary uses a
 * 9-feature weighted sigmoid where inlier_count is the dominant
 * feature (weight 188145, bias 711041). 4 inliers alone exceeds
 * the bias, so 4+ nearly always matches. We approximate:
 *   score = inlier_count * 1250 (3→3750, 4→5000, ..., 8→10000)
 */
static int
mafp_compute_match_score (int n_inliers)
{
  if (n_inliers < MAFP_MIN_MATCH_PTS)
    return 0;
  if (n_inliers >= 8)
    return 10000;
  return MIN (n_inliers * 1250, 10000);
}

/* ── Top-level template matching ── */

static int
mafp_match_templates (const guint8 *probe, const guint8 *gallery)
{
  MafpCorr corrs[60];   /* 2 banks × max 15 matches */
  int n_corrs = 0;

  for (int bank = 0; bank < MAFP_NUM_BANKS; bank++)
    {
      const guint8 *pb = probe   + 4 + bank * MAFP_BANK_SZ;
      const guint8 *gb = gallery + 4 + bank * MAFP_BANK_SZ;
      int bank_matches = 0;

      gint32 np, ng;
      memcpy (&np, pb, 4);  np = MIN (np, MAFP_MAX_KP);
      memcpy (&ng, gb, 4);  ng = MIN (ng, MAFP_MAX_KP);

      const guint8 *pk = pb + 4, *gk = gb + 4;

      for (int pi = 0; pi < np && bank_matches < MAFP_MAX_MATCHES; pi++)
        {
          const guint8 *pd = pk + pi * MAFP_KP_SIZE;
          int best = 999, second = 999, best_gi = -1;

          for (int gi = 0; gi < ng; gi++)
            {
              int d = mafp_hamming (pd, gk + gi * MAFP_KP_SIZE);
              if (d < best)
                { second = best; best = d; best_gi = gi; }
              else if (d < second)
                second = d;
            }

          /* Ratio test: best*256 < second*219 (≈0.855, from binary) */
          if (best_gi >= 0 && best < MAFP_HAMMING_THRESH &&
              (second >= 999 || best * 256 < second * MAFP_HAMMING_RATIO))
            {
              fp_dbg ("  corr: p(%d,%d)->g(%d,%d) ham=%d/%d",
                      pd[16], pd[17],
                      gk[best_gi * MAFP_KP_SIZE + 16],
                      gk[best_gi * MAFP_KP_SIZE + 17],
                      best, second);
              corrs[n_corrs].pr = pd[16];
              corrs[n_corrs].pc = pd[17];
              corrs[n_corrs].gr = gk[best_gi * MAFP_KP_SIZE + 16];
              corrs[n_corrs].gc = gk[best_gi * MAFP_KP_SIZE + 17];
              n_corrs++;
              bank_matches++;
            }
        }
    }

  /* Deduplicate: keep only the best match per gallery keypoint
   * (the binary's uniquePoints function does this) */
  {
    gboolean used_g[60] = {0};
    int deduped = 0;
    for (int i = 0; i < n_corrs; i++)
      {
        /* Check if this gallery position was already matched by a better pair */
        gboolean dup = FALSE;
        for (int j = 0; j < deduped; j++)
          if (corrs[j].gr == corrs[i].gr && corrs[j].gc == corrs[i].gc)
            { dup = TRUE; break; }
        if (!dup)
          corrs[deduped++] = corrs[i];
      }
    fp_dbg ("match: %d correspondences (%d after dedup)", n_corrs, deduped);
    n_corrs = deduped;
  }

  if (n_corrs < MAFP_MIN_MATCH_PTS)
    return 0;

  /* Exhaustive pairwise RANSAC (matching binary's approach) */
  int best_inliers = 0;
  gdouble best_avg_dist = 1e9;

  for (int i = 0; i < n_corrs - 1; i++)
    for (int j = i + 1; j < n_corrs; j++)
      {
        MafpCorr pair[2] = { corrs[i], corrs[j] };
        gdouble a, b, tx, ty;
        if (!mafp_solve_similarity (pair, &a, &b, &tx, &ty))
          continue;

        /* Count inliers with pixel-space threshold (~3 px distance) */
        gdouble avg_d = 0;
        MafpCorr inliers_buf[MAFP_MAX_INLIERS];
        int inl = mafp_count_inliers (corrs, n_corrs, a, b, tx, ty,
                                       inliers_buf, &avg_d);

        if (inl >= MAFP_MAX_INLIERS)
          { best_inliers = inl; best_avg_dist = avg_d; goto done; }

        if (inl >= MAFP_MIN_MATCH_PTS)
          {
            /* Refit transform from inliers only (matching binary) */
            if (inl >= 2)
              {
                MafpCorr rpair[2] = { inliers_buf[0], inliers_buf[1] };
                gdouble ra, rb, rtx, rty;
                if (mafp_solve_similarity (rpair, &ra, &rb, &rtx, &rty))
                  {
                    gdouble ravg = 0;
                    int rinl = mafp_count_inliers (corrs, n_corrs,
                                                    ra, rb, rtx, rty,
                                                    NULL, &ravg);
                    if (rinl > inl || (rinl == inl && ravg < avg_d))
                      { inl = rinl; avg_d = ravg; }
                  }
              }

            if (inl > best_inliers ||
                (inl == best_inliers && avg_d < best_avg_dist))
              { best_inliers = inl; best_avg_dist = avg_d; }
          }
      }

done:;
  int score = mafp_compute_match_score (best_inliers);
  fp_info ("match: inliers=%d avg_dist=%.1f score=%d (thresh=%d)",
           best_inliers, best_avg_dist, score, MAFP_MATCH_THRESH);
  return score;
}

/* ─── check cancellation ─────────────────────────────────────────── */

static gboolean
mafp_is_canceled (FpiDeviceMafp8800 *self)
{
  return self->canceled || fpi_device_action_is_cancelled (FP_DEVICE (self));
}

/* ─── enroll (runs in worker thread) ─────────────────────────────── */

static void
mafp_enroll_run (FpiDeviceMafp8800 *self)
{
  fp_info ("enroll: starting");

  /* Calibrate (loads from file or runs live) */
  mafp_fp36_calibrate (self);

  /* Enter detection mode with calibrated thresholds */
  mafp_fp36_detect_mode (self);

  /* Allocate template buffer */
  g_autofree guint8 *tpl_buf = g_malloc0 (MAFP_TPL_BUF_SZ);
  int tpl_count = 0;

  for (int stage = 0; stage < MAFP_ENROLL_STAGES; stage++)
    {
      if (mafp_is_canceled (self))
        goto canceled;

      fp_info ("enroll: stage %d/%d — waiting for finger", stage + 1, MAFP_ENROLL_STAGES);

      /* Reset detection state */
      self->detect_flag = FALSE;
      self->gray_value = 0;

      /* Wait for finger */
      while (!mafp_is_canceled (self))
        {
          if (mafp_fp36_finger_is_detect (self))
            break;
          g_usleep (50000);
        }
      if (mafp_is_canceled (self))
        goto canceled;

      fp_info ("enroll: finger detected, waiting for stable");

      /* Wait for stable */
      memcpy (self->stab_frame, self->cur_frame, MAFP_FRAME_BYTES);
      gboolean stable = FALSE;
      for (int tries = 0; tries < 20; tries++)
        {
          g_usleep (50000);
          mafp_fp36_capture (self, self->cur_frame);
          if (!mafp_fp36_finger_is_detect (self))
            break;
          if (mafp_fp36_finger_is_stable (self))
            { stable = TRUE; break; }
          memcpy (self->stab_frame, self->cur_frame, MAFP_FRAME_BYTES);
        }

      if (!stable)
        {
          fp_info ("enroll: not stable, retrying stage");
          fpi_device_enroll_progress (FP_DEVICE (self), stage, NULL,
            fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
          stage--;
          continue;
        }

      fp_info ("enroll: stable, capturing template");

      /* Enhance image and extract keypoint features */
      mafp_fp36_enhance (self);
      mafp_extract_features (self->enhanced,
                             tpl_buf + MAFP_TPL_HDR_SZ + tpl_count * MAFP_TPL_SAMPLE_SZ);
      tpl_count++;

      fpi_device_enroll_progress (FP_DEVICE (self), stage, NULL, NULL);

      fp_info ("enroll: stage %d done, waiting for finger removal", stage + 1);

      /* Wait for finger removal */
      while (!mafp_is_canceled (self))
        {
          g_usleep (100000);
          self->detect_flag = FALSE;
          self->gray_value = 0;
          if (!mafp_fp36_finger_is_detect (self))
            break;
        }
    }

  if (mafp_is_canceled (self))
    goto canceled;

  /* Store template count and serialize */
  memcpy (tpl_buf, &tpl_count, sizeof (gint32));

  FpPrint *print = NULL;
  fpi_device_get_enroll_data (FP_DEVICE (self), &print);
  GVariant *data = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                               tpl_buf, MAFP_TPL_BUF_SZ, 1);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, FALSE);
  g_object_set (print, "fpi-data", data, NULL);

  fp_info ("enroll: complete, %d templates", tpl_count);
  fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (print), NULL);
  return;

canceled:
  fp_info ("enroll: canceled");
  fpi_device_enroll_complete (FP_DEVICE (self), NULL,
    fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
}

/* ─── verify/identify (runs in worker thread) ────────────────────── */

static void
mafp_verify_run (FpiDeviceMafp8800 *self)
{
  FpiDeviceAction action = fpi_device_get_current_action (FP_DEVICE (self));

  fp_info ("verify/identify: starting");

  mafp_fp36_calibrate (self);
  mafp_fp36_detect_mode (self);

  /* Reset detection */
  self->detect_flag = FALSE;
  self->gray_value = 0;

  /* Wait for finger */
  while (!mafp_is_canceled (self))
    {
      if (mafp_fp36_finger_is_detect (self))
        break;
      g_usleep (50000);
    }

  if (mafp_is_canceled (self))
    goto canceled;

  /* Wait for stable */
  memcpy (self->stab_frame, self->cur_frame, MAFP_FRAME_BYTES);
  for (int i = 0; i < 20; i++)
    {
      g_usleep (50000);
      mafp_fp36_capture (self, self->cur_frame);
      if (mafp_fp36_finger_is_stable (self))
        break;
      memcpy (self->stab_frame, self->cur_frame, MAFP_FRAME_BYTES);
    }

  /* Enhance and extract features */
  mafp_fp36_enhance (self);
  guint8 probe_tpl[MAFP_TPL_SAMPLE_SZ];
  mafp_extract_features (self->enhanced, probe_tpl);

  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *enrolled = NULL;
      fpi_device_get_verify_data (FP_DEVICE (self), &enrolled);

      g_autoptr (GVariant) var = NULL;
      g_object_get (enrolled, "fpi-data", &var, NULL);

      gboolean matched = FALSE;
      if (var)
        {
          gsize tpl_sz = 0;
          const guint8 *tpl = g_variant_get_fixed_array (var, &tpl_sz, 1);
          if (tpl_sz >= MAFP_TPL_HDR_SZ)
            {
              gint32 count = 0;
              memcpy (&count, tpl, sizeof (gint32));
              for (int i = 0; i < count && i < MAFP_ENROLL_STAGES; i++)
                {
                  const guint8 *sample = tpl + MAFP_TPL_HDR_SZ + i * MAFP_TPL_SAMPLE_SZ;
                  int score = mafp_match_templates (probe_tpl, sample);
                  fp_info ("verify: template %d score=%d (thresh=%d)",
                           i, score, MAFP_MATCH_THRESH);
                  if (score >= MAFP_MATCH_THRESH)
                    { matched = TRUE; break; }
                }
            }
        }

      fpi_device_verify_report (FP_DEVICE (self),
                                 matched ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                                 NULL, NULL);
      fpi_device_verify_complete (FP_DEVICE (self), NULL);
    }
  else /* IDENTIFY */
    {
      GPtrArray *gallery = NULL;
      fpi_device_get_identify_data (FP_DEVICE (self), &gallery);

      FpPrint *matched_print = NULL;
      for (guint gi = 0; gi < gallery->len; gi++)
        {
          FpPrint *p = g_ptr_array_index (gallery, gi);
          g_autoptr (GVariant) var = NULL;
          g_object_get (p, "fpi-data", &var, NULL);
          if (!var) continue;

          gsize tpl_sz = 0;
          const guint8 *tpl = g_variant_get_fixed_array (var, &tpl_sz, 1);
          if (tpl_sz < MAFP_TPL_HDR_SZ) continue;

          gint32 count = 0;
          memcpy (&count, tpl, sizeof (gint32));
          for (int i = 0; i < count && i < MAFP_ENROLL_STAGES; i++)
            {
              const guint8 *sample = tpl + MAFP_TPL_HDR_SZ + i * MAFP_TPL_SAMPLE_SZ;
              if (mafp_match_templates (probe_tpl, sample) >= MAFP_MATCH_THRESH)
                { matched_print = p; goto id_done; }
            }
        }
id_done:
      fpi_device_identify_report (FP_DEVICE (self), matched_print, NULL, NULL);
      fpi_device_identify_complete (FP_DEVICE (self), NULL);
    }
  return;

canceled:
  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_ERROR, NULL,
        fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      fpi_device_verify_complete (FP_DEVICE (self), NULL);
    }
  else
    {
      fpi_device_identify_report (FP_DEVICE (self), NULL, NULL,
        fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      fpi_device_identify_complete (FP_DEVICE (self), NULL);
    }
}

/* ─── worker thread ──────────────────────────────────────────────── */

static gpointer
mafp_worker (gpointer data)
{
  FpiDeviceMafp8800 *self = FPI_DEVICE_MAFP8800 (data);

  while (TRUE)
    {
      g_mutex_lock (&self->lock);
      while (!self->has_work && !self->exit_flag)
        g_cond_wait (&self->cond, &self->lock);

      if (self->exit_flag)
        { g_mutex_unlock (&self->lock); break; }

      self->has_work = FALSE;
      self->canceled = FALSE;
      void (*func)(FpiDeviceMafp8800 *) = self->run_func;
      g_mutex_unlock (&self->lock);

      if (func)
        func (self);
    }
  return NULL;
}

static void
mafp_dispatch (FpiDeviceMafp8800 *self, void (*func)(FpiDeviceMafp8800 *))
{
  g_mutex_lock (&self->lock);
  self->run_func = func;
  self->has_work = TRUE;
  self->canceled = FALSE;
  g_cond_signal (&self->cond);
  g_mutex_unlock (&self->lock);
}

/* ─── FpDevice callbacks ─────────────────────────────────────────── */

static void
mafp_open (FpDevice *dev)
{
  FpiDeviceMafp8800 *self = FPI_DEVICE_MAFP8800 (dev);
  const char *path = fpi_device_get_udev_data (dev, FPI_DEVICE_UDEV_SUBTYPE_SPIDEV);

  fp_info ("opening %s", path ? path : "(null)");

  if (!path)
    {
      fpi_device_open_complete (dev,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "no spidev path"));
      return;
    }

  self->spi_fd = open (path, O_RDWR);
  if (self->spi_fd < 0)
    {
      fpi_device_open_complete (dev,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                  "open %s: %s", path, g_strerror (errno)));
      return;
    }

  guint8 mode = SPI_MODE_0;
  guint8 bpw = 8;
  guint32 speed = MAFP_SPI_SPEED;
  ioctl (self->spi_fd, SPI_IOC_WR_MODE, &mode);
  ioctl (self->spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bpw);
  ioctl (self->spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);

  /* Verify chip */
  if (!mafp_fp36_reset (self))
    {
      close (self->spi_fd); self->spi_fd = -1;
      fpi_device_open_complete (dev,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "chip not responding"));
      return;
    }

  gint id = mafp_set_reg (self, 0x04, 0x00);
  fp_info ("chip ID=0x%02x", id);
  if (id != MAFP_CHIPID_FP36)
    {
      close (self->spi_fd); self->spi_fd = -1;
      fpi_device_open_complete (dev,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                  "unsupported chip 0x%02x", id));
      return;
    }

  /* Allocate buffers */
  self->bg_frame   = g_malloc0 (MAFP_FRAME_BYTES);
  self->cur_frame  = g_malloc0 (MAFP_FRAME_BYTES);
  self->stab_frame = g_malloc0 (MAFP_FRAME_BYTES);
  self->detect_ref = g_malloc0 (MAFP_FRAME_BYTES);
  self->enhanced   = g_new0 (guint16, MAFP_ENHANCED_PIXELS);
  self->spi_buf    = g_malloc0 (MAFP_RAW_READ_SZ);

  /* Start worker */
  g_mutex_init (&self->lock);
  g_cond_init (&self->cond);
  self->exit_flag = FALSE;
  self->worker = g_thread_new ("mafp", mafp_worker, self);

  fpi_device_open_complete (dev, NULL);
}

static void
mafp_close (FpDevice *dev)
{
  FpiDeviceMafp8800 *self = FPI_DEVICE_MAFP8800 (dev);

  if (self->worker)
    {
      g_mutex_lock (&self->lock);
      self->exit_flag = TRUE;
      g_cond_signal (&self->cond);
      g_mutex_unlock (&self->lock);
      g_thread_join (self->worker);
      self->worker = NULL;
    }
  g_mutex_clear (&self->lock);
  g_cond_clear (&self->cond);

  g_clear_pointer (&self->bg_frame, g_free);
  g_clear_pointer (&self->cur_frame, g_free);
  g_clear_pointer (&self->stab_frame, g_free);
  g_clear_pointer (&self->detect_ref, g_free);
  g_clear_pointer (&self->enhanced, g_free);
  g_clear_pointer (&self->spi_buf, g_free);

  if (self->spi_fd >= 0)
    { close (self->spi_fd); self->spi_fd = -1; }

  fpi_device_close_complete (dev, NULL);
}

static void mafp_enroll (FpDevice *dev) { mafp_dispatch (FPI_DEVICE_MAFP8800 (dev), mafp_enroll_run); }
static void mafp_verify (FpDevice *dev) { mafp_dispatch (FPI_DEVICE_MAFP8800 (dev), mafp_verify_run); }

static void
mafp_cancel (FpDevice *dev)
{
  FpiDeviceMafp8800 *self = FPI_DEVICE_MAFP8800 (dev);
  g_mutex_lock (&self->lock);
  self->canceled = TRUE;
  g_mutex_unlock (&self->lock);
}

/* ─── GObject ────────────────────────────────────────────────────── */

static const FpIdEntry mafp_id_table[] = {
  { .udev_types = FPI_DEVICE_UDEV_SUBTYPE_SPIDEV,
    .spi_acpi_id = "MAFP8800", .driver_data = 0 },
  { .udev_types = 0 }
};

static void fpi_device_mafp8800_init (FpiDeviceMafp8800 *self) { self->spi_fd = -1; }

static void
fpi_device_mafp8800_finalize (GObject *obj)
{
  FpiDeviceMafp8800 *self = FPI_DEVICE_MAFP8800 (obj);
  g_clear_pointer (&self->bg_frame, g_free);
  g_clear_pointer (&self->cur_frame, g_free);
  g_clear_pointer (&self->stab_frame, g_free);
  g_clear_pointer (&self->detect_ref, g_free);
  g_clear_pointer (&self->enhanced, g_free);
  g_clear_pointer (&self->spi_buf, g_free);
  if (self->spi_fd >= 0) close (self->spi_fd);
  G_OBJECT_CLASS (fpi_device_mafp8800_parent_class)->finalize (obj);
}

static void
fpi_device_mafp8800_class_init (FpiDeviceMafp8800Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id               = "mafp8800";
  dev_class->full_name        = "Microarray MAFP Fingerprint Sensor";
  dev_class->type             = FP_DEVICE_TYPE_UDEV;
  dev_class->id_table         = mafp_id_table;
  dev_class->scan_type        = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = MAFP_ENROLL_STAGES;

  dev_class->open     = mafp_open;
  dev_class->close    = mafp_close;
  dev_class->enroll   = mafp_enroll;
  dev_class->verify   = mafp_verify;
  dev_class->identify = mafp_verify;
  dev_class->cancel   = mafp_cancel;

  G_OBJECT_CLASS (klass)->finalize = fpi_device_mafp8800_finalize;

  fpi_device_class_auto_initialize_features (dev_class);
}
