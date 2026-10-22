/*
 * Minimalist GObject bridge for Egis Technology (LighTuning) Match-On-Chip sensors
 * Delegates all SDCP cryptography, packet framing, checksums, and state machines
 * to the Rust staticlib (libegismoc_core.a).
 *
 * License: LGPL-2.1-or-later
 */

#define FP_COMPONENT "egismoc"

#include <glib.h>
#include "drivers_api.h"
#include "egismoc.h"

struct _FpiDeviceEgisMoc
{
  FpDevice      parent;
  EgisMocRs    *rs;
  gint64        wait_finger_start;
  GCancellable *interrupt_cancellable;
};

G_DEFINE_TYPE (FpiDeviceEgisMoc, fpi_device_egismoc, FP_TYPE_DEVICE);

static const FpIdEntry egismoc_id_table[] = {
  { .vid = 0x1c7a, .pid = 0x0582, .driver_data = EGISMOC_RS_FLAG_CHECK_PREFIX_TYPE1 },
  { .vid = 0x1c7a, .pid = 0x0583, .driver_data = EGISMOC_RS_FLAG_CHECK_PREFIX_TYPE1 | EGISMOC_RS_FLAG_MAX_ENROLL_STAGES_15 },
  { .vid = 0x1c7a, .pid = 0x0584, .driver_data = EGISMOC_RS_FLAG_CHECK_PREFIX_TYPE1 | EGISMOC_RS_FLAG_MAX_ENROLL_STAGES_20 },
  { .vid = 0x1c7a, .pid = 0x0586, .driver_data = EGISMOC_RS_FLAG_CHECK_PREFIX_TYPE1 | EGISMOC_RS_FLAG_MAX_ENROLL_STAGES_20 },
  { .vid = 0x1c7a, .pid = 0x0587, .driver_data = EGISMOC_RS_FLAG_CHECK_PREFIX_TYPE1 | EGISMOC_RS_FLAG_MAX_ENROLL_STAGES_20 },
  { .vid = 0x1c7a, .pid = 0x05a1, .driver_data = EGISMOC_RS_FLAG_CHECK_PREFIX_TYPE2 },
  { .vid = 0x1c7a, .pid = 0x05a5, .driver_data = EGISMOC_RS_FLAG_CHECK_PREFIX_TYPE2 | EGISMOC_RS_FLAG_MAX_ENROLL_STAGES_15 },
  { .vid = 0,      .pid = 0,      .driver_data = 0 }
};

static void egismoc_drive_rust (FpDevice      *device,
                                const guint8  *rx_buf,
                                gsize          rx_len);

static void
egismoc_ensure_rs (FpiDeviceEgisMoc *self)
{
  FpDevice *device = FP_DEVICE (self);

  if (!self->rs)
    self->rs = egismoc_rs_new (fpi_device_get_driver_data (device));

  if (fp_device_get_device_id (device) != NULL)
    {
      egismoc_rs_set_device_id (self->rs,
                                fp_device_get_driver (device),
                                fp_device_get_device_id (device));
    }
}

static void
egismoc_set_print_data (FpPrint       *print,
                        const guint8  *enrollment_id)
{
  GVariant *fpi_data = NULL;
  GVariant *enrollment_id_var = NULL;

  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);

  enrollment_id_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                 enrollment_id,
                                                 EGISMOC_RS_ENROLLMENT_ID_SIZE,
                                                 sizeof (guint8));
  fpi_data = g_variant_new ("(@ay)", enrollment_id_var);
  g_object_set (print, "fpi-data", fpi_data, NULL);
}

static void
egismoc_fail_current_action (FpDevice *device,
                             GError   *error)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  self->wait_finger_start = 0;
  if (self->rs)
    egismoc_rs_cancel (self->rs);

  if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_OPEN)
    g_usb_device_release_interface (fpi_device_get_usb_device (device), 0, 0, NULL);

  fpi_device_action_error (device, error);
}

static GError *
egismoc_map_rs_error (EgisMocErrorKind kind)
{
  switch (kind)
    {
    case EGISMOC_RS_ERROR_PROTO:
      return fpi_device_error_new (FP_DEVICE_ERROR_PROTO);
    case EGISMOC_RS_ERROR_DATA_INVALID:
      return fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID);
    case EGISMOC_RS_ERROR_DATA_NOT_FOUND:
      return fpi_device_error_new (FP_DEVICE_ERROR_DATA_NOT_FOUND);
    case EGISMOC_RS_ERROR_DATA_FULL:
      return fpi_device_error_new (FP_DEVICE_ERROR_DATA_FULL);
    case EGISMOC_RS_ERROR_DATA_DUPLICATE:
      return fpi_device_error_new (FP_DEVICE_ERROR_DATA_DUPLICATE);
    case EGISMOC_RS_ERROR_GENERAL:
    case EGISMOC_RS_ERROR_NONE:
    default:
      return fpi_device_error_new (FP_DEVICE_ERROR_GENERAL);
    }
}

static void
egismoc_usb_rx_cb (FpiUsbTransfer *transfer,
                   FpDevice       *device,
                   gpointer        userdata,
                   GError         *error)
{
  if (error)
    {
      egismoc_fail_current_action (device, error);
      return;
    }

  egismoc_drive_rust (device, transfer->buffer, (gsize) transfer->actual_length);
}

static void
egismoc_cmd_tx_done_cb (FpiUsbTransfer *transfer,
                        FpDevice       *device,
                        gpointer        userdata,
                        GError         *error)
{
  g_autoptr(FpiUsbTransfer) rx_transfer = NULL;

  if (error)
    {
      egismoc_fail_current_action (device, error);
      return;
    }

  rx_transfer = fpi_usb_transfer_new (device);
  fpi_usb_transfer_fill_bulk (rx_transfer,
                              EGISMOC_EP_CMD_IN,
                              EGISMOC_USB_IN_RECV_LENGTH);
  fpi_usb_transfer_submit (g_steal_pointer (&rx_transfer),
                           EGISMOC_USB_RECV_TIMEOUT,
                           fpi_device_get_cancellable (device),
                           egismoc_usb_rx_cb,
                           NULL);
}

static void
egismoc_wait_finger_on_sensor (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  g_autoptr(FpiUsbTransfer) transfer = NULL;

  if (self->wait_finger_start == 0)
    {
      self->wait_finger_start = g_get_monotonic_time ();
      fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
    }

  if (self->wait_finger_start + EGISMOC_FINGER_ON_SENSOR_TIMEOUT_USEC <= g_get_monotonic_time ())
    {
      egismoc_fail_current_action (device,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                             "Timed out trying to detect finger on sensor"));
      return;
    }

  transfer = fpi_usb_transfer_new (device);
  fpi_usb_transfer_fill_interrupt (transfer,
                                   EGISMOC_EP_CMD_INTERRUPT_IN,
                                   EGISMOC_USB_INTERRUPT_IN_RECV_LENGTH);
  transfer->short_is_error = FALSE;

  fpi_usb_transfer_submit (g_steal_pointer (&transfer),
                           EGISMOC_USB_INTERRUPT_TIMEOUT,
                           self->interrupt_cancellable,
                           egismoc_usb_rx_cb,
                           NULL);
}

static void
egismoc_report_enroll_progress (FpDevice            *device,
                                const EgisMocAction *action)
{
  FpPrint *enroll_print = NULL;
  GError *retry_err = NULL;

  if (!action->has_enroll_progress)
    return;

  fpi_device_get_enroll_data (device, &enroll_print);

  switch (action->enroll_capture_status)
    {
    case EGISMOC_RS_CAPTURE_SUCCESS:
      fpi_device_enroll_progress (device, action->enroll_stage, enroll_print, NULL);
      break;
    case EGISMOC_RS_CAPTURE_OFF_CENTER:
      retry_err = fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);
      fpi_device_enroll_progress (device, action->enroll_stage, NULL, retry_err);
      break;
    case EGISMOC_RS_CAPTURE_DIRTY_SENSOR:
      retry_err = fpi_device_retry_new_msg (FP_DEVICE_RETRY_REMOVE_FINGER,
                                            "Your device is having trouble recognizing you. "
                                            "Make sure your sensor is clean.");
      fpi_device_enroll_progress (device, action->enroll_stage, NULL, retry_err);
      break;
    case EGISMOC_RS_CAPTURE_RETRY_UNKNOWN:
    default:
      retry_err = fpi_device_retry_new_msg (FP_DEVICE_RETRY_REMOVE_FINGER,
                                            "Unknown failure trying to read your finger. "
                                            "Please try again.");
      fpi_device_enroll_progress (device, action->enroll_stage, NULL, retry_err);
      break;
    }
}

static void
egismoc_handle_task_complete (FpDevice            *device,
                              const EgisMocAction *action)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  self->wait_finger_start = 0;

  switch (action->result_kind)
    {
    case EGISMOC_RS_RESULT_PROBE_COMPLETE:
      fpi_device_open_complete (device, NULL);
      break;

    case EGISMOC_RS_RESULT_LIST_COMPLETE:
      {
        g_autoptr(GPtrArray) result = g_ptr_array_new_with_free_func (g_object_unref);
        for (size_t i = 0; i < action->enrolled_ids_count; i++)
          {
            guint8 id[EGISMOC_RS_ENROLLMENT_ID_SIZE];
            if (egismoc_rs_get_enrolled_id (self->rs, i, id))
              {
                FpPrint *print = fp_print_new (device);
                egismoc_set_print_data (print, id);
                g_ptr_array_add (result, g_object_ref_sink (print));
              }
          }
        fpi_device_list_complete (device, g_steal_pointer (&result), NULL);
      }
      break;

    case EGISMOC_RS_RESULT_IDENTIFY_COMPLETE:
      if (action->has_matched_id)
        {
          FpPrint *print = fp_print_new (device);
          egismoc_set_print_data (print, action->enrollment_id);

          if (action->identity_verification == EGISMOC_RS_IDENTITY_MAC_MISMATCH_AFTER_RESET)
            fp_dbg ("SDCP AuthorizedIdentity MAC mismatch after USB reset; relying on enrollment_id match");

          if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_IDENTIFY)
            {
              GPtrArray *prints = NULL;
              guint index = 0;
              fpi_device_get_identify_data (device, &prints);
              if (prints && g_ptr_array_find_with_equal_func (prints, print, (GEqualFunc) fp_print_equal, &index))
                fpi_device_identify_report (device, g_ptr_array_index (prints, index), print, NULL);
              else
                fpi_device_identify_report (device, NULL, print, NULL);
              fpi_device_identify_complete (device, NULL);
            }
          else
            {
              FpPrint *verify_print = NULL;
              fpi_device_get_verify_data (device, &verify_print);
              if (fp_print_equal (verify_print, print))
                fpi_device_verify_report (device, FPI_MATCH_SUCCESS, print, NULL);
              else
                fpi_device_verify_report (device, FPI_MATCH_FAIL, print, NULL);
              fpi_device_verify_complete (device, NULL);
            }
        }
      else
        {
          if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_VERIFY)
            {
              fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
              fpi_device_verify_complete (device, NULL);
            }
          else
            {
              fpi_device_identify_report (device, NULL, NULL, NULL);
              fpi_device_identify_complete (device, NULL);
            }
        }
      break;

    case EGISMOC_RS_RESULT_ENROLL_COMPLETE:
      {
        FpPrint *enroll_print = NULL;
        fpi_device_get_enroll_data (device, &enroll_print);
        egismoc_set_print_data (enroll_print, action->enrollment_id);
        fpi_device_enroll_complete (device, g_object_ref (enroll_print), NULL);
      }
      break;

    case EGISMOC_RS_RESULT_DELETE_COMPLETE:
      fpi_device_delete_complete (device, NULL);
      break;

    case EGISMOC_RS_RESULT_CLEAR_STORAGE_COMPLETE:
      fpi_device_clear_storage_complete (device, NULL);
      break;

    case EGISMOC_RS_RESULT_NONE:
    default:
      break;
    }
}

static void
egismoc_drive_rust (FpDevice     *device,
                    const guint8 *rx_buf,
                    gsize         rx_len)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  EgisMocAction action = {0};

  egismoc_rs_step (self->rs, rx_buf, rx_len, &action);

  switch (action.kind)
    {
    case EGISMOC_RS_ACTION_IDLE:
      break;

    case EGISMOC_RS_ACTION_CONTROL_TRANSFER:
      {
        g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new (device);
        transfer->short_is_error = TRUE;
        fpi_usb_transfer_fill_control (transfer,
                                       (GUsbDeviceDirection) action.ctrl_direction,
                                       (GUsbDeviceRequestType) action.ctrl_request_type,
                                       (GUsbDeviceRecipient) action.ctrl_recipient,
                                       action.ctrl_request,
                                       action.ctrl_value,
                                       action.ctrl_index,
                                       action.ctrl_length);
        fpi_usb_transfer_submit (g_steal_pointer (&transfer),
                                 EGISMOC_USB_CONTROL_TIMEOUT,
                                 fpi_device_get_cancellable (device),
                                 egismoc_usb_rx_cb,
                                 NULL);
      }
      break;

    case EGISMOC_RS_ACTION_SEND_COMMAND:
      {
        g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new (device);
        guint8 *tx_copy = g_memdup2 (action.tx_ptr, action.tx_len);

        if (action.report_finger_present)
          {
            self->wait_finger_start = 0;
            fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
          }

        egismoc_report_enroll_progress (device, &action);

        transfer->short_is_error = TRUE;
        fpi_usb_transfer_fill_bulk_full (transfer,
                                         EGISMOC_EP_CMD_OUT,
                                         tx_copy,
                                         action.tx_len,
                                         g_free);
        fpi_usb_transfer_submit (g_steal_pointer (&transfer),
                                 EGISMOC_USB_SEND_TIMEOUT,
                                 fpi_device_get_cancellable (device),
                                 egismoc_cmd_tx_done_cb,
                                 NULL);
      }
      break;

    case EGISMOC_RS_ACTION_WAIT_FINGER:
      egismoc_report_enroll_progress (device, &action);
      egismoc_wait_finger_on_sensor (device);
      break;

    case EGISMOC_RS_ACTION_TASK_COMPLETE:
      egismoc_handle_task_complete (device, &action);
      break;

    case EGISMOC_RS_ACTION_ERROR:
      egismoc_fail_current_action (device, egismoc_map_rs_error (action.error_kind));
      break;
    }
}

static void
egismoc_probe (FpDevice *device)
{
  GUsbDevice *usb_dev;
  GError *error = NULL;
  g_autofree gchar *serial = NULL;
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  egismoc_ensure_rs (self);

  usb_dev = fpi_device_get_usb_device (device);
  if (!g_usb_device_open (usb_dev, &error))
    {
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  if (!g_usb_device_reset (usb_dev, &error))
    {
      g_usb_device_close (usb_dev, NULL);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  if (!g_usb_device_claim_interface (usb_dev, 0, 0, &error))
    {
      g_usb_device_close (usb_dev, NULL);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  if (g_strcmp0 (g_getenv ("FP_DEVICE_EMULATION"), "1") == 0)
    serial = g_strdup ("emulated-device");
  else
    serial = g_usb_device_get_string_descriptor (usb_dev,
                                                 g_usb_device_get_serial_number_index (usb_dev),
                                                 &error);

  if (error)
    {
      g_usb_device_release_interface (usb_dev, 0, 0, NULL);
      g_usb_device_close (usb_dev, NULL);
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  fpi_device_set_nr_enroll_stages (device, egismoc_rs_max_enroll_stages (self->rs));

  g_usb_device_release_interface (usb_dev, 0, 0, NULL);
  g_usb_device_close (usb_dev, NULL);

  fpi_device_probe_complete (device, serial, NULL, NULL);
}

static void
egismoc_open (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  GError *error = NULL;

  egismoc_ensure_rs (self);
  egismoc_rs_set_device_id (self->rs,
                            fp_device_get_driver (device),
                            fp_device_get_device_id (device));

  g_clear_object (&self->interrupt_cancellable);
  self->interrupt_cancellable = g_cancellable_new ();

  if (!g_usb_device_reset (fpi_device_get_usb_device (device), &error))
    {
      fpi_device_open_complete (device, error);
      return;
    }

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (device), 0, 0, &error))
    {
      fpi_device_open_complete (device, error);
      return;
    }

  egismoc_rs_start_probe (self->rs);
  egismoc_drive_rust (device, NULL, 0);
}

static void
egismoc_cancel (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);

  self->wait_finger_start = 0;
  if (self->rs)
    egismoc_rs_cancel (self->rs);

  if (self->interrupt_cancellable)
    {
      g_cancellable_cancel (self->interrupt_cancellable);
      g_clear_object (&self->interrupt_cancellable);
      self->interrupt_cancellable = g_cancellable_new ();
    }
}

static void
egismoc_suspend (FpDevice *device)
{
  egismoc_cancel (device);
  g_cancellable_cancel (fpi_device_get_cancellable (device));
  fpi_device_suspend_complete (device, NULL);
}

static void
egismoc_close (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  GError *error = NULL;

  egismoc_cancel (device);
  g_clear_object (&self->interrupt_cancellable);

  g_usb_device_release_interface (fpi_device_get_usb_device (device), 0, 0, &error);
  fpi_device_close_complete (device, error);
}

static void
egismoc_list (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  egismoc_ensure_rs (self);
  egismoc_rs_start_list (self->rs);
  egismoc_drive_rust (device, NULL, 0);
}

static void
egismoc_identify_verify (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  egismoc_ensure_rs (self);
  egismoc_rs_start_identify (self->rs);
  egismoc_drive_rust (device, NULL, 0);
}

static void
egismoc_enroll (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  egismoc_ensure_rs (self);
  egismoc_rs_start_enroll (self->rs);
  egismoc_drive_rust (device, NULL, 0);
}

static void
egismoc_delete (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  FpPrint *delete_print = NULL;
  g_autoptr(GVariant) print_data = NULL;
  g_autoptr(GVariant) enrollment_id_var = NULL;
  const guint8 *enrollment_id = NULL;
  gsize enrollment_id_len = 0;

  egismoc_ensure_rs (self);
  fpi_device_get_delete_data (device, &delete_print);
  g_object_get (delete_print, "fpi-data", &print_data, NULL);

  if (!print_data || !g_variant_check_format_string (print_data, "(@ay)", FALSE))
    {
      fpi_device_delete_complete (device, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      return;
    }

  g_variant_get (print_data, "(@ay)", &enrollment_id_var);
  enrollment_id = g_variant_get_fixed_array (enrollment_id_var, &enrollment_id_len, sizeof (guint8));
  if (!enrollment_id || enrollment_id_len != EGISMOC_RS_ENROLLMENT_ID_SIZE)
    {
      fpi_device_delete_complete (device, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      return;
    }

  egismoc_rs_start_delete (self->rs, enrollment_id);
  egismoc_drive_rust (device, NULL, 0);
}

static void
egismoc_clear_storage (FpDevice *device)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (device);
  egismoc_ensure_rs (self);
  egismoc_rs_start_clear_storage (self->rs);
  egismoc_drive_rust (device, NULL, 0);
}

static void
fpi_device_egismoc_finalize (GObject *object)
{
  FpiDeviceEgisMoc *self = FPI_DEVICE_EGISMOC (object);

  g_clear_object (&self->interrupt_cancellable);
  if (self->rs)
    {
      egismoc_rs_free (self->rs);
      self->rs = NULL;
    }

  G_OBJECT_CLASS (fpi_device_egismoc_parent_class)->finalize (object);
}

static void
fpi_device_egismoc_init (FpiDeviceEgisMoc *self)
{
}

static void
fpi_device_egismoc_class_init (FpiDeviceEgisMocClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_egismoc_finalize;

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = EGISMOC_DRIVER_FULLNAME;

  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = egismoc_id_table;
  dev_class->nr_enroll_stages = EGISMOC_MAX_ENROLL_STAGES_DEFAULT;
  dev_class->temp_hot_seconds = 0;

  dev_class->probe = egismoc_probe;
  dev_class->open = egismoc_open;
  dev_class->cancel = egismoc_cancel;
  dev_class->suspend = egismoc_suspend;
  dev_class->close = egismoc_close;
  dev_class->identify = egismoc_identify_verify;
  dev_class->verify = egismoc_identify_verify;
  dev_class->enroll = egismoc_enroll;
  dev_class->delete = egismoc_delete;
  dev_class->clear_storage = egismoc_clear_storage;
  dev_class->list = egismoc_list;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_DUPLICATES_CHECK;
}
