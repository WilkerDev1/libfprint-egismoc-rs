/*
 * Minimalist GObject bridge for Egis Technology (LighTuning) Match-On-Chip sensors
 * Connects libfprint's asynchronous USB transfer API to the Sans-I/O Rust driver core (egismoc-core).
 *
 * License: LGPL-2.1-or-later
 */

#pragma once

#include "fpi-device.h"
#include "egismoc_rs.h"

G_DECLARE_FINAL_TYPE (FpiDeviceEgisMoc, fpi_device_egismoc, FPI, DEVICE_EGISMOC, FpDevice)

#define EGISMOC_DRIVER_FULLNAME "Egis Technology (LighTuning) Match-on-Chip"

#define EGISMOC_EP_CMD_OUT (0x02 | FPI_USB_ENDPOINT_OUT)
#define EGISMOC_EP_CMD_IN (0x81 | FPI_USB_ENDPOINT_IN)
#define EGISMOC_EP_CMD_INTERRUPT_IN 0x83

#define EGISMOC_USB_CONTROL_TIMEOUT 5000
#define EGISMOC_USB_SEND_TIMEOUT 5000
#define EGISMOC_USB_RECV_TIMEOUT 5000
#define EGISMOC_USB_INTERRUPT_TIMEOUT 60000

#define EGISMOC_USB_IN_RECV_LENGTH 4096
#define EGISMOC_USB_INTERRUPT_IN_RECV_LENGTH 64

#define EGISMOC_MAX_ENROLL_STAGES_DEFAULT 10
#define EGISMOC_FINGER_ON_SENSOR_TIMEOUT_USEC (10 * G_USEC_PER_SEC)
