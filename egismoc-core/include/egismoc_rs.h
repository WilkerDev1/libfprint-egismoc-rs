/*
 * Interfaz C ABI del núcleo en Rust (egismoc-core) para libfprint
 * Dispositivos soportados: Egis Technology Match-on-Chip (1c7a:0582 - 1c7a:05a5)
 * Licencia: LGPL-2.1-or-later
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EGISMOC_RS_ENROLLMENT_ID_SIZE 32

#define EGISMOC_RS_FLAG_CHECK_PREFIX_TYPE1 (1ULL << 0)
#define EGISMOC_RS_FLAG_CHECK_PREFIX_TYPE2 (1ULL << 1)
#define EGISMOC_RS_FLAG_MAX_ENROLL_STAGES_20 (1ULL << 2)
#define EGISMOC_RS_FLAG_MAX_ENROLL_STAGES_15 (1ULL << 3)

typedef struct EgisMocRs EgisMocRs;

typedef enum {
  EGISMOC_RS_ACTION_IDLE = 0,
  EGISMOC_RS_ACTION_CONTROL_TRANSFER = 1,
  EGISMOC_RS_ACTION_SEND_COMMAND = 2,
  EGISMOC_RS_ACTION_WAIT_FINGER = 3,
  EGISMOC_RS_ACTION_TASK_COMPLETE = 4,
  EGISMOC_RS_ACTION_ERROR = 5,
} EgisMocActionKind;

typedef enum {
  EGISMOC_RS_CAPTURE_SUCCESS = 0,
  EGISMOC_RS_CAPTURE_OFF_CENTER = 1,
  EGISMOC_RS_CAPTURE_DIRTY_SENSOR = 2,
  EGISMOC_RS_CAPTURE_RETRY_UNKNOWN = 3,
} EgisMocCaptureStatus;

typedef enum {
  EGISMOC_RS_RESULT_NONE = 0,
  EGISMOC_RS_RESULT_PROBE_COMPLETE = 1,
  EGISMOC_RS_RESULT_LIST_COMPLETE = 2,
  EGISMOC_RS_RESULT_IDENTIFY_COMPLETE = 3,
  EGISMOC_RS_RESULT_ENROLL_COMPLETE = 4,
  EGISMOC_RS_RESULT_DELETE_COMPLETE = 5,
  EGISMOC_RS_RESULT_CLEAR_STORAGE_COMPLETE = 6,
} EgisMocResultKind;

typedef enum {
  EGISMOC_RS_IDENTITY_VERIFIED = 0,
  EGISMOC_RS_IDENTITY_MAC_MISMATCH_AFTER_RESET = 1,
  EGISMOC_RS_IDENTITY_NOT_CONNECTED = 2,
} EgisMocIdentityVerification;

typedef enum {
  EGISMOC_RS_ERROR_NONE = 0,
  EGISMOC_RS_ERROR_GENERAL = 1,
  EGISMOC_RS_ERROR_PROTO = 2,
  EGISMOC_RS_ERROR_DATA_INVALID = 3,
  EGISMOC_RS_ERROR_DATA_NOT_FOUND = 4,
  EGISMOC_RS_ERROR_DATA_FULL = 5,
  EGISMOC_RS_ERROR_DATA_DUPLICATE = 6,
} EgisMocErrorKind;

typedef struct {
  EgisMocActionKind kind;

  /* ControlTransfer */
  uint8_t ctrl_direction;
  uint8_t ctrl_request_type;
  uint8_t ctrl_recipient;
  uint8_t ctrl_request;
  uint16_t ctrl_value;
  uint16_t ctrl_index;
  size_t ctrl_length;

  /* SendCommand */
  const uint8_t *tx_ptr;
  size_t tx_len;
  bool report_finger_present;

  /* Enroll progress */
  bool has_enroll_progress;
  int32_t enroll_stage;
  EgisMocCaptureStatus enroll_capture_status;

  /* TaskComplete */
  EgisMocResultKind result_kind;
  bool has_matched_id;
  uint8_t enrollment_id[EGISMOC_RS_ENROLLMENT_ID_SIZE];
  EgisMocIdentityVerification identity_verification;
  size_t enrolled_ids_count;

  /* Error */
  EgisMocErrorKind error_kind;
} EgisMocAction;

EgisMocRs *egismoc_rs_new (uint64_t driver_data);
void egismoc_rs_free (EgisMocRs *ctx);

void egismoc_rs_set_device_id (EgisMocRs  *ctx,
                               const char *driver_name,
                               const char *device_id);

int32_t egismoc_rs_max_enroll_stages (const EgisMocRs *ctx);

void egismoc_rs_cancel (EgisMocRs *ctx);
void egismoc_rs_start_probe (EgisMocRs *ctx);
void egismoc_rs_start_list (EgisMocRs *ctx);
void egismoc_rs_start_identify (EgisMocRs *ctx);
void egismoc_rs_start_enroll (EgisMocRs *ctx);
void egismoc_rs_start_delete (EgisMocRs *ctx, const uint8_t *target_id);
void egismoc_rs_start_clear_storage (EgisMocRs *ctx);

bool egismoc_rs_get_enrolled_id (const EgisMocRs *ctx,
                                 size_t           index,
                                 uint8_t         *out_id);

void egismoc_rs_step (EgisMocRs     *ctx,
                      const uint8_t *rx_ptr,
                      size_t         rx_len,
                      EgisMocAction *out_action);

#ifdef __cplusplus
}
#endif
