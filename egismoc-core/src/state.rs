//! Máquina de estados **Sans-I/O** pura para el driver Egis Technology Match-on-Chip (`1c7a:0582`).
//!
//! Toda la lógica de control de flujo (`Probe`/`Open`, `List`, `Identify`/`Verify`, `Enroll`,
//! `Delete`, `ClearStorage`) avanza exclusivamente a través de `step(&mut self, rx: Option<&[u8]>) -> Action`,
//! sin realizar llamadas de E/S ni depender de `FpiSsm` o `GMainLoop`.

use crate::protocol::{
    build_check_payload, build_delete_payload, build_new_print_payload,
    build_sdcp_connect_payload, is_finger_present_interrupt, parse_enroll_starting_response,
    parse_fw_version_response, parse_identify_check_response, parse_list_response,
    parse_read_capture_response, validate_response_prefix, validate_response_suffix,
    wrap_egui_frame, CaptureReadStatus, IdentifyCheckResult, CMD_CAPTURE_POST_WAIT_FINGER,
    CMD_COMMIT_STARTING, CMD_ENROLL_STARTING, CMD_FW_VERSION, CMD_LIST, CMD_READ_CAPTURE,
    CMD_SENSOR_CHECK, CMD_SENSOR_ENROLL, CMD_SENSOR_IDENTIFY, CMD_SENSOR_RESET,
    CMD_SENSOR_START_CAPTURE, EGISMOC_DRIVER_CHECK_PREFIX_TYPE2,
    EGISMOC_DRIVER_MAX_ENROLL_STAGES_15, EGISMOC_DRIVER_MAX_ENROLL_STAGES_20,
    EGISMOC_MAX_ENROLL_NUM, EGISMOC_MAX_ENROLL_STAGES_DEFAULT,
    RSP_CHECK_NOT_YET_ENROLLED_SUFFIX, RSP_COMMIT_SUCCESS_SUFFIX, RSP_DELETE_SUCCESS_PREFIX,
};
use crate::sdcp::{
    IdentityVerification, SdcpConnectResponse, SdcpSession, SDCP_ENROLLMENT_ID_SIZE,
    SDCP_NONCE_SIZE,
};

/// Variantes de modelo de la familia Egis Match-on-Chip (`1c7a:0582` – `1c7a:05a5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelVariant {
    /// `0x0582` (10 etapas) y `0x0583` (15 etapas) con prefijo Check Type 1 (`50 17 03 00 00`).
    ModelType1,
    /// `0x0584`–`0x0587` (20 etapas) y `0x05a1`/`0x05a5` (prefijo Check Type 2 `50 17 03 80 00`).
    ModelType2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbDirection {
    DeviceToHost = 0,
    HostToDevice = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbRequestType {
    Standard = 0,
    Class = 1,
    Vendor = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbRecipient {
    Device = 0,
    Interface = 1,
    Endpoint = 2,
    Other = 3,
}

/// Progreso parcial emitido durante `Enroll` antes de enviar el siguiente comando USB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollProgress {
    pub completed_stages: i32,
    pub status: CaptureReadStatus,
    pub enrollment_id: Option<[u8; SDCP_ENROLLMENT_ID_SIZE]>,
}

/// Errores de alto nivel mapeables directamente a `FpDeviceError` / `FpDeviceRetry` en `libfprint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    General(&'static str),
    Proto(&'static str),
    DataInvalid(&'static str),
    DataNotFound(&'static str),
    DataFull,
    DataDuplicate,
}

/// Resultado final al completarse una tarea de la máquina de estados.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskResult {
    ProbeComplete {
        fw_version: String,
        max_enroll_stages: i32,
    },
    ListComplete {
        enrolled_ids: Vec<[u8; SDCP_ENROLLMENT_ID_SIZE]>,
    },
    IdentifyComplete {
        matched_enrollment_id: Option<[u8; SDCP_ENROLLMENT_ID_SIZE]>,
        verification: Option<IdentityVerification>,
    },
    EnrollComplete {
        enrollment_id: [u8; SDCP_ENROLLMENT_ID_SIZE],
    },
    DeleteComplete,
    ClearStorageComplete,
}

/// Acción determinista devuelta por `EgisMocDriver::step()` al puente de E/S.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// No hay tarea activa.
    Idle,
    /// Ejecutar una transferencia USB de control (usada en los 5 pasos pre-open de `Probe`/`Open`).
    ControlTransfer {
        direction: UsbDirection,
        request_type: UsbRequestType,
        recipient: UsbRecipient,
        request: u8,
        value: u16,
        index: u16,
        length: usize,
    },
    /// Enviar un comando empaquetado con prefijo `EGIS` por Bulk OUT (`0x02`) y recibir respuesta por Bulk IN (`0x81`).
    SendCommand {
        packet: Vec<u8>,
        finger_present: bool,
        enroll_progress: Option<EnrollProgress>,
    },
    /// Esperar interrupción de dedo en el sensor por Interrupt IN (`0x83`).
    WaitFingerOnSensor {
        enroll_progress: Option<EnrollProgress>,
    },
    /// La tarea activa finalizó con éxito.
    TaskComplete(TaskResult),
    /// La tarea activa falló con un error de dispositivo/protocolo.
    Error(DriverError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStep {
    Control1,
    Control2,
    Control3,
    Control4,
    Control5,
    GetFwVersion,
    WaitFwVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListStep {
    SendList,
    WaitList,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifyStep {
    Start,
    WaitSdcpConnect,
    WaitEnrolledIds,
    WaitSensorReset,
    WaitSensorIdentify,
    WaitFinger,
    WaitSensorCheck,
    WaitCheck,
    WaitCompleteSensorReset {
        matched_id: Option<[u8; SDCP_ENROLLMENT_ID_SIZE]>,
        verification: Option<IdentityVerification>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollStep {
    Start,
    WaitSdcpConnect,
    WaitEnrolledIds,
    WaitSensorReset,
    WaitSensorEnroll,
    WaitFinger,
    WaitSensorCheck,
    WaitCheck,
    WaitEnrollStarting,
    WaitCaptureSensorReset,
    WaitCaptureSensorStart,
    WaitCaptureFinger,
    WaitCapturePostWaitFinger,
    WaitCaptureReadResponse,
    WaitCommitStart,
    WaitCommit,
    WaitCommitSensorReset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteStep {
    Start,
    WaitEnrolledIds,
    WaitDeleteResponse,
}

/// Estado activo de la máquina de estados Sans-I/O (`TaskState`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    Probe {
        step: ProbeStep,
    },
    List {
        step: ListStep,
    },
    Identify {
        step: IdentifyStep,
    },
    Enroll {
        step: EnrollStep,
        stage: i32,
        enrollment_nonce: [u8; SDCP_NONCE_SIZE],
        enrollment_id: [u8; SDCP_ENROLLMENT_ID_SIZE],
    },
    Delete {
        step: DeleteStep,
        target_id: [u8; SDCP_ENROLLMENT_ID_SIZE],
    },
    ClearStorage {
        step: DeleteStep,
    },
}

/// Instancia principal Sans-I/O del driver Egis Match-on-Chip.
pub struct EgisMocDriver {
    pub model_variant: ModelVariant,
    pub use_type2_check_prefix: bool,
    pub max_enroll_stages: i32,
    pub sdcp: SdcpSession,
    pub enrolled_ids: Vec<[u8; SDCP_ENROLLMENT_ID_SIZE]>,
    pub fw_version: Option<String>,
    pub task: Option<TaskState>,
}

impl EgisMocDriver {
    /// Crea una instancia configurada según los flags `driver_data` de `libfprint`.
    pub fn from_driver_data(driver_data: u64) -> Self {
        let use_type2_check_prefix = (driver_data & EGISMOC_DRIVER_CHECK_PREFIX_TYPE2) != 0;
        let max_enroll_stages = if (driver_data & EGISMOC_DRIVER_MAX_ENROLL_STAGES_20) != 0 {
            20
        } else if (driver_data & EGISMOC_DRIVER_MAX_ENROLL_STAGES_15) != 0 {
            15
        } else {
            EGISMOC_MAX_ENROLL_STAGES_DEFAULT
        };

        let model_variant = if use_type2_check_prefix || max_enroll_stages == 20 {
            ModelVariant::ModelType2
        } else {
            ModelVariant::ModelType1
        };

        Self {
            model_variant,
            use_type2_check_prefix,
            max_enroll_stages,
            sdcp: SdcpSession::new(),
            enrolled_ids: Vec::new(),
            fw_version: None,
            task: None,
        }
    }

    /// Crea una instancia a partir del USB Product ID (`0x0582`–`0x05a5`).
    pub fn from_pid(pid: u16) -> Self {
        match pid {
            0x0582 => Self::from_driver_data(0),
            0x0583 => Self::from_driver_data(EGISMOC_DRIVER_MAX_ENROLL_STAGES_15),
            0x0584 | 0x0586 | 0x0587 => Self::from_driver_data(EGISMOC_DRIVER_MAX_ENROLL_STAGES_20),
            0x05a1 => Self::from_driver_data(EGISMOC_DRIVER_CHECK_PREFIX_TYPE2),
            0x05a5 => Self::from_driver_data(
                EGISMOC_DRIVER_CHECK_PREFIX_TYPE2 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_15,
            ),
            _ => Self::from_driver_data(0),
        }
    }

    /// Cancela limpiamente cualquier tarea activa descartando `self.task`.
    /// Hace imposible el fallo `assertion failed: (self->task_ssm == NULL)` de la versión en C.
    pub fn cancel(&mut self) {
        self.task = None;
    }

    pub fn start_probe(&mut self) {
        self.task = Some(TaskState::Probe {
            step: ProbeStep::Control1,
        });
    }

    pub fn start_list(&mut self) {
        self.task = Some(TaskState::List {
            step: ListStep::SendList,
        });
    }

    pub fn start_identify(&mut self) {
        self.task = Some(TaskState::Identify {
            step: IdentifyStep::Start,
        });
    }

    pub fn start_enroll(&mut self) {
        self.task = Some(TaskState::Enroll {
            step: EnrollStep::Start,
            stage: 0,
            enrollment_nonce: [0u8; SDCP_NONCE_SIZE],
            enrollment_id: [0u8; SDCP_ENROLLMENT_ID_SIZE],
        });
    }

    pub fn start_delete(&mut self, target_id: [u8; SDCP_ENROLLMENT_ID_SIZE]) {
        self.task = Some(TaskState::Delete {
            step: DeleteStep::Start,
            target_id,
        });
    }

    pub fn start_clear_storage(&mut self) {
        self.task = Some(TaskState::ClearStorage {
            step: DeleteStep::Start,
        });
    }

    /// Avanza un paso en la máquina de estados Sans-I/O entregando opcionalmente los bytes recibidos `rx`.
    pub fn step(&mut self, rx: Option<&[u8]>) -> Action {
        let Some(current_task) = self.task.take() else {
            return Action::Idle;
        };

        match current_task {
            TaskState::Probe { step } => self.step_probe(step, rx),
            TaskState::List { step } => self.step_list(step, rx),
            TaskState::Identify { step } => self.step_identify(step, rx),
            TaskState::Enroll {
                step,
                stage,
                enrollment_nonce,
                enrollment_id,
            } => self.step_enroll(step, stage, enrollment_nonce, enrollment_id, rx),
            TaskState::Delete { step, target_id } => self.step_delete(step, Some(target_id), rx),
            TaskState::ClearStorage { step } => self.step_delete(step, None, rx),
        }
    }

    fn step_probe(&mut self, step: ProbeStep, rx: Option<&[u8]>) -> Action {
        match step {
            ProbeStep::Control1 => {
                self.task = Some(TaskState::Probe {
                    step: ProbeStep::Control2,
                });
                Action::ControlTransfer {
                    direction: UsbDirection::DeviceToHost,
                    request_type: UsbRequestType::Vendor,
                    recipient: UsbRecipient::Device,
                    request: 32,
                    value: 0x0000,
                    index: 4,
                    length: 16,
                }
            }
            ProbeStep::Control2 => {
                self.task = Some(TaskState::Probe {
                    step: ProbeStep::Control3,
                });
                Action::ControlTransfer {
                    direction: UsbDirection::DeviceToHost,
                    request_type: UsbRequestType::Vendor,
                    recipient: UsbRecipient::Device,
                    request: 32,
                    value: 0x0000,
                    index: 4,
                    length: 40,
                }
            }
            ProbeStep::Control3 => {
                self.task = Some(TaskState::Probe {
                    step: ProbeStep::Control4,
                });
                Action::ControlTransfer {
                    direction: UsbDirection::DeviceToHost,
                    request_type: UsbRequestType::Standard,
                    recipient: UsbRecipient::Device,
                    request: 0,
                    value: 0x0000,
                    index: 0,
                    length: 2,
                }
            }
            ProbeStep::Control4 => {
                self.task = Some(TaskState::Probe {
                    step: ProbeStep::Control5,
                });
                Action::ControlTransfer {
                    direction: UsbDirection::DeviceToHost,
                    request_type: UsbRequestType::Standard,
                    recipient: UsbRecipient::Device,
                    request: 0,
                    value: 0x0000,
                    index: 0,
                    length: 2,
                }
            }
            ProbeStep::Control5 => {
                self.task = Some(TaskState::Probe {
                    step: ProbeStep::GetFwVersion,
                });
                Action::ControlTransfer {
                    direction: UsbDirection::DeviceToHost,
                    request_type: UsbRequestType::Vendor,
                    recipient: UsbRecipient::Device,
                    request: 82,
                    value: 0x0000,
                    index: 0,
                    length: 8,
                }
            }
            ProbeStep::GetFwVersion => {
                self.task = Some(TaskState::Probe {
                    step: ProbeStep::WaitFwVersion,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_FW_VERSION),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            ProbeStep::WaitFwVersion => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::Proto("Missing fw_version response"));
                };
                match parse_fw_version_response(buf) {
                    Ok(fw_ver) => {
                        self.fw_version = Some(fw_ver.clone());
                        Action::TaskComplete(TaskResult::ProbeComplete {
                            fw_version: fw_ver,
                            max_enroll_stages: self.max_enroll_stages,
                        })
                    }
                    Err(_) => Action::Error(DriverError::Proto(
                        "Device firmware response was not valid",
                    )),
                }
            }
        }
    }

    fn step_list(&mut self, step: ListStep, rx: Option<&[u8]>) -> Action {
        match step {
            ListStep::SendList => {
                self.task = Some(TaskState::List {
                    step: ListStep::WaitList,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_LIST),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            ListStep::WaitList => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::General("Missing list response"));
                };
                match parse_list_response(buf) {
                    Ok(ids) => {
                        self.enrolled_ids = ids.clone();
                        Action::TaskComplete(TaskResult::ListComplete { enrolled_ids: ids })
                    }
                    Err(_) => Action::Error(DriverError::General("Invalid list response")),
                }
            }
        }
    }

    fn step_identify(&mut self, step: IdentifyStep, rx: Option<&[u8]>) -> Action {
        match step {
            IdentifyStep::Start => {
                if self.sdcp.is_connected() {
                    self.task = Some(TaskState::Identify {
                        step: IdentifyStep::WaitEnrolledIds,
                    });
                    Action::SendCommand {
                        packet: wrap_egui_frame(&CMD_LIST),
                        finger_present: false,
                        enroll_progress: None,
                    }
                } else {
                    let Ok(host_random) = self.sdcp.host_random() else {
                        return Action::Error(DriverError::Proto("Failed to get SDCP host random"));
                    };
                    let Ok(host_pub) = self.sdcp.host_public_key() else {
                        return Action::Error(DriverError::Proto("Failed to get SDCP host key"));
                    };
                    let payload = build_sdcp_connect_payload(&host_random, &host_pub);
                    self.task = Some(TaskState::Identify {
                        step: IdentifyStep::WaitSdcpConnect,
                    });
                    Action::SendCommand {
                        packet: wrap_egui_frame(&payload),
                        finger_present: false,
                        enroll_progress: None,
                    }
                }
            }
            IdentifyStep::WaitSdcpConnect => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::DataInvalid("Missing SDCP ConnectResponse"));
                };
                let resp = match SdcpConnectResponse::from_egismoc_frame(buf) {
                    Ok(r) => r,
                    Err(_) => {
                        return Action::Error(DriverError::DataInvalid(
                            "Device responded with failure instead of SDCP ConnectResponse",
                        ))
                    }
                };
                if self.sdcp.derive_keys_and_verify_connect(&resp).is_err() {
                    return Action::Error(DriverError::Proto(
                        "Secure connection could not be established",
                    ));
                }
                self.task = Some(TaskState::Identify {
                    step: IdentifyStep::WaitEnrolledIds,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_LIST),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            IdentifyStep::WaitEnrolledIds => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::General("Missing list response"));
                };
                let Ok(ids) = parse_list_response(buf) else {
                    return Action::Error(DriverError::General("Failed to parse enrolled IDs"));
                };
                self.enrolled_ids = ids;
                if self.enrolled_ids.is_empty() {
                    return Action::Error(DriverError::DataNotFound(
                        "No prints currently enrolled on the device",
                    ));
                }
                self.task = Some(TaskState::Identify {
                    step: IdentifyStep::WaitSensorReset,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_SENSOR_RESET),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            IdentifyStep::WaitSensorReset => {
                self.task = Some(TaskState::Identify {
                    step: IdentifyStep::WaitSensorIdentify,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_SENSOR_IDENTIFY),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            IdentifyStep::WaitSensorIdentify => {
                self.task = Some(TaskState::Identify {
                    step: IdentifyStep::WaitFinger,
                });
                Action::WaitFingerOnSensor {
                    enroll_progress: None,
                }
            }
            IdentifyStep::WaitFinger => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::General("Missing interrupt payload"));
                };
                if is_finger_present_interrupt(buf) {
                    self.task = Some(TaskState::Identify {
                        step: IdentifyStep::WaitSensorCheck,
                    });
                    Action::SendCommand {
                        packet: wrap_egui_frame(&CMD_SENSOR_CHECK),
                        finger_present: true,
                        enroll_progress: None,
                    }
                } else {
                    self.task = Some(TaskState::Identify {
                        step: IdentifyStep::WaitFinger,
                    });
                    Action::WaitFingerOnSensor {
                        enroll_progress: None,
                    }
                }
            }
            IdentifyStep::WaitSensorCheck => {
                let payload =
                    build_check_payload(&self.enrolled_ids, self.use_type2_check_prefix);
                self.task = Some(TaskState::Identify {
                    step: IdentifyStep::WaitCheck,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&payload),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            IdentifyStep::WaitCheck => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::Proto("Missing identify check response"));
                };
                match parse_identify_check_response(buf) {
                    Ok(IdentifyCheckResult::Match {
                        device_mac,
                        enrollment_id,
                    }) => {
                        let host_nonce = [0u8; SDCP_NONCE_SIZE];
                        let verification = self.sdcp.verify_authorized_identity(
                            &host_nonce,
                            &enrollment_id,
                            &device_mac,
                        );
                        self.task = Some(TaskState::Identify {
                            step: IdentifyStep::WaitCompleteSensorReset {
                                matched_id: Some(enrollment_id),
                                verification: Some(verification),
                            },
                        });
                        Action::SendCommand {
                            packet: wrap_egui_frame(&CMD_SENSOR_RESET),
                            finger_present: false,
                            enroll_progress: None,
                        }
                    }
                    Ok(IdentifyCheckResult::NoMatch) => {
                        self.task = Some(TaskState::Identify {
                            step: IdentifyStep::WaitCompleteSensorReset {
                                matched_id: None,
                                verification: None,
                            },
                        });
                        Action::SendCommand {
                            packet: wrap_egui_frame(&CMD_SENSOR_RESET),
                            finger_present: false,
                            enroll_progress: None,
                        }
                    }
                    Err(_) => Action::Error(DriverError::Proto(
                        "Unrecognized response from device",
                    )),
                }
            }
            IdentifyStep::WaitCompleteSensorReset {
                matched_id,
                verification,
            } => Action::TaskComplete(TaskResult::IdentifyComplete {
                matched_enrollment_id: matched_id,
                verification,
            }),
        }
    }

    fn step_enroll(
        &mut self,
        step: EnrollStep,
        mut stage: i32,
        mut enrollment_nonce: [u8; SDCP_NONCE_SIZE],
        mut enrollment_id: [u8; SDCP_ENROLLMENT_ID_SIZE],
        rx: Option<&[u8]>,
    ) -> Action {
        match step {
            EnrollStep::Start => {
                let skip_connect = std::env::var("FP_DEVICE_EMULATION").as_deref() == Ok("1")
                    && self.sdcp.is_connected();
                if skip_connect {
                    self.task = Some(TaskState::Enroll {
                        step: EnrollStep::WaitEnrolledIds,
                        stage,
                        enrollment_nonce,
                        enrollment_id,
                    });
                    return Action::SendCommand {
                        packet: wrap_egui_frame(&CMD_LIST),
                        finger_present: false,
                        enroll_progress: None,
                    };
                }

                let Ok(host_random) = self.sdcp.host_random() else {
                    return Action::Error(DriverError::Proto("Failed to get SDCP host random"));
                };
                let Ok(host_pub) = self.sdcp.host_public_key() else {
                    return Action::Error(DriverError::Proto("Failed to get SDCP host key"));
                };
                let payload = build_sdcp_connect_payload(&host_random, &host_pub);
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitSdcpConnect,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&payload),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitSdcpConnect => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::DataInvalid("Missing SDCP ConnectResponse"));
                };
                let resp = match SdcpConnectResponse::from_egismoc_frame(buf) {
                    Ok(r) => r,
                    Err(_) => {
                        return Action::Error(DriverError::DataInvalid(
                            "Device responded with failure instead of SDCP ConnectResponse",
                        ))
                    }
                };
                if self.sdcp.derive_keys_and_verify_connect(&resp).is_err() {
                    return Action::Error(DriverError::Proto(
                        "Secure connection could not be established",
                    ));
                }
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitEnrolledIds,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_LIST),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitEnrolledIds => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::General("Missing list response"));
                };
                let Ok(ids) = parse_list_response(buf) else {
                    return Action::Error(DriverError::General("Failed to parse enrolled IDs"));
                };
                self.enrolled_ids = ids;
                if self.enrolled_ids.len() >= EGISMOC_MAX_ENROLL_NUM {
                    return Action::Error(DriverError::DataFull);
                }
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitSensorReset,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_SENSOR_RESET),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitSensorReset => {
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitSensorEnroll,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_SENSOR_ENROLL),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitSensorEnroll => {
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitFinger,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::WaitFingerOnSensor {
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitFinger => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::General("Missing interrupt payload"));
                };
                if is_finger_present_interrupt(buf) {
                    self.task = Some(TaskState::Enroll {
                        step: EnrollStep::WaitSensorCheck,
                        stage,
                        enrollment_nonce,
                        enrollment_id,
                    });
                    Action::SendCommand {
                        packet: wrap_egui_frame(&CMD_SENSOR_CHECK),
                        finger_present: true,
                        enroll_progress: None,
                    }
                } else {
                    self.task = Some(TaskState::Enroll {
                        step: EnrollStep::WaitFinger,
                        stage,
                        enrollment_nonce,
                        enrollment_id,
                    });
                    Action::WaitFingerOnSensor {
                        enroll_progress: None,
                    }
                }
            }
            EnrollStep::WaitSensorCheck => {
                let payload =
                    build_check_payload(&self.enrolled_ids, self.use_type2_check_prefix);
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitCheck,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&payload),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitCheck => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::Proto("Missing enroll check response"));
                };
                if !validate_response_suffix(buf, &RSP_CHECK_NOT_YET_ENROLLED_SUFFIX) {
                    return Action::Error(DriverError::DataDuplicate);
                }
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitEnrollStarting,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_ENROLL_STARTING),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitEnrollStarting => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::Proto("Missing enroll starting response"));
                };
                let Ok(nonce) = parse_enroll_starting_response(buf) else {
                    return Action::Error(DriverError::Proto(
                        "Invalid response when starting enrollment",
                    ));
                };
                enrollment_nonce = nonce;
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitCaptureSensorReset,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_SENSOR_RESET),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitCaptureSensorReset => {
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitCaptureSensorStart,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_SENSOR_START_CAPTURE),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitCaptureSensorStart => {
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitCaptureFinger,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::WaitFingerOnSensor {
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitCaptureFinger => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::General("Missing interrupt payload"));
                };
                if is_finger_present_interrupt(buf) {
                    self.task = Some(TaskState::Enroll {
                        step: EnrollStep::WaitCapturePostWaitFinger,
                        stage,
                        enrollment_nonce,
                        enrollment_id,
                    });
                    Action::SendCommand {
                        packet: wrap_egui_frame(&CMD_CAPTURE_POST_WAIT_FINGER),
                        finger_present: true,
                        enroll_progress: None,
                    }
                } else {
                    self.task = Some(TaskState::Enroll {
                        step: EnrollStep::WaitCaptureFinger,
                        stage,
                        enrollment_nonce,
                        enrollment_id,
                    });
                    Action::WaitFingerOnSensor {
                        enroll_progress: None,
                    }
                }
            }
            EnrollStep::WaitCapturePostWaitFinger => {
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitCaptureReadResponse,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_READ_CAPTURE),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitCaptureReadResponse => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::Proto("Missing capture read response"));
                };
                let status = parse_read_capture_response(buf);
                if status == CaptureReadStatus::Success {
                    stage += 1;
                }
                let progress = Some(EnrollProgress {
                    completed_stages: stage,
                    status,
                    enrollment_id: None,
                });

                if stage >= self.max_enroll_stages {
                    self.task = Some(TaskState::Enroll {
                        step: EnrollStep::WaitCommitStart,
                        stage,
                        enrollment_nonce,
                        enrollment_id,
                    });
                    Action::SendCommand {
                        packet: wrap_egui_frame(&CMD_COMMIT_STARTING),
                        finger_present: false,
                        enroll_progress: progress,
                    }
                } else {
                    self.task = Some(TaskState::Enroll {
                        step: EnrollStep::WaitCaptureSensorReset,
                        stage,
                        enrollment_nonce,
                        enrollment_id,
                    });
                    Action::SendCommand {
                        packet: wrap_egui_frame(&CMD_SENSOR_RESET),
                        finger_present: false,
                        enroll_progress: progress,
                    }
                }
            }
            EnrollStep::WaitCommitStart => {
                let Ok(gen_id) = self.sdcp.generate_enrollment_id(&enrollment_nonce) else {
                    return Action::Error(DriverError::Proto("Failed to generate enrollment ID"));
                };
                enrollment_id = gen_id;
                let payload = build_new_print_payload(&enrollment_id);
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitCommit,
                    stage,
                    enrollment_nonce,
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&payload),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitCommit => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::DataInvalid("Missing commit response"));
                };
                if !validate_response_suffix(buf, &RSP_COMMIT_SUCCESS_SUFFIX) {
                    return Action::Error(DriverError::DataInvalid(
                        "Enrollment was rejected by the device",
                    ));
                }
                self.task = Some(TaskState::Enroll {
                    step: EnrollStep::WaitCommitSensorReset,
                    stage,
                    enrollment_nonce: [0u8; SDCP_NONCE_SIZE],
                    enrollment_id,
                });
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_SENSOR_RESET),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            EnrollStep::WaitCommitSensorReset => {
                Action::TaskComplete(TaskResult::EnrollComplete { enrollment_id })
            }
        }
    }

    fn step_delete(
        &mut self,
        step: DeleteStep,
        target_id: Option<[u8; SDCP_ENROLLMENT_ID_SIZE]>,
        rx: Option<&[u8]>,
    ) -> Action {
        let wrap_state = |next_step: DeleteStep| match target_id {
            Some(id) => TaskState::Delete {
                step: next_step,
                target_id: id,
            },
            None => TaskState::ClearStorage { step: next_step },
        };

        match step {
            DeleteStep::Start => {
                self.task = Some(wrap_state(DeleteStep::WaitEnrolledIds));
                Action::SendCommand {
                    packet: wrap_egui_frame(&CMD_LIST),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            DeleteStep::WaitEnrolledIds => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::General("Missing list response"));
                };
                let Ok(ids) = parse_list_response(buf) else {
                    return Action::Error(DriverError::General("Failed to parse enrolled IDs"));
                };
                self.enrolled_ids = ids;

                let payload = if let Some(id) = target_id {
                    build_delete_payload(&[id])
                } else {
                    if self.enrolled_ids.is_empty() {
                        return Action::Error(DriverError::DataNotFound(
                            "Clear attempted when there are no prints currently stored on the device",
                        ));
                    }
                    build_delete_payload(&self.enrolled_ids)
                };

                self.task = Some(wrap_state(DeleteStep::WaitDeleteResponse));
                Action::SendCommand {
                    packet: wrap_egui_frame(&payload),
                    finger_present: false,
                    enroll_progress: None,
                }
            }
            DeleteStep::WaitDeleteResponse => {
                let Some(buf) = rx else {
                    return Action::Error(DriverError::Proto("Missing delete response"));
                };
                if validate_response_prefix(buf, &RSP_DELETE_SUCCESS_PREFIX) {
                    if target_id.is_some() {
                        Action::TaskComplete(TaskResult::DeleteComplete)
                    } else {
                        Action::TaskComplete(TaskResult::ClearStorageComplete)
                    }
                } else {
                    Action::Error(DriverError::Proto("Delete print was not successful"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        EGISMOC_ENROLL_STARTING_RESPONSE_PREFIX_SIZE, EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE,
        EGISMOC_LIST_RESPONSE_PREFIX_SIZE, EGISMOC_READ_PREFIX, RSP_ENROLL_STARTING_SUFFIX,
        RSP_FW_VERSION_SUFFIX, RSP_IDENTIFY_MATCH_SUFFIX, RSP_READ_SUCCESS_SUFFIX,
        RSP_SENSOR_HAS_FINGER_SUFFIX,
    };

    fn make_ok_resp() -> Vec<u8> {
        let mut v = EGISMOC_READ_PREFIX.to_vec();
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x90, 0x00]);
        v
    }

    fn make_interrupt_finger_present() -> Vec<u8> {
        let mut v = EGISMOC_READ_PREFIX.to_vec();
        v.extend_from_slice(&RSP_SENSOR_HAS_FINGER_SUFFIX);
        v
    }

    #[test]
    fn test_probe_flow_and_model_variants() {
        let mut drv1 = EgisMocDriver::from_pid(0x0582);
        assert_eq!(drv1.model_variant, ModelVariant::ModelType1);
        assert_eq!(drv1.max_enroll_stages, 10);

        let drv2 = EgisMocDriver::from_pid(0x0584);
        assert_eq!(drv2.model_variant, ModelVariant::ModelType2);
        assert_eq!(drv2.max_enroll_stages, 20);

        drv1.start_probe();
        // 5 transferencias de control pre-open
        for expected_len in [16usize, 40, 2, 2, 8] {
            match drv1.step(None) {
                Action::ControlTransfer { length, .. } => assert_eq!(length, expected_len),
                other => panic!("Expected ControlTransfer, got {:?}", other),
            }
        }
        // Envío de cmd_fw_version
        match drv1.step(None) {
            Action::SendCommand { packet, .. } => {
                assert_eq!(packet, wrap_egui_frame(&CMD_FW_VERSION));
            }
            other => panic!("Expected SendCommand(CMD_FW_VERSION), got {:?}", other),
        }
        // Respuesta de fw_version: 8B prefix + 2B check + 3B zero + 0x0d + "01.23" + 90 00
        let mut fw_rsp = EGISMOC_READ_PREFIX.to_vec();
        fw_rsp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x0d]);
        fw_rsp.extend_from_slice(b"01.23");
        fw_rsp.extend_from_slice(&RSP_FW_VERSION_SUFFIX);

        match drv1.step(Some(&fw_rsp)) {
            Action::TaskComplete(TaskResult::ProbeComplete {
                fw_version,
                max_enroll_stages,
            }) => {
                assert_eq!(fw_version, "01.23");
                assert_eq!(max_enroll_stages, 10);
            }
            other => panic!("Expected ProbeComplete, got {:?}", other),
        }
        assert!(drv1.task.is_none());
    }

    #[test]
    fn test_list_and_delete_flows() {
        let mut drv = EgisMocDriver::from_pid(0x0582);
        let id1 = [0x42u8; 32];

        drv.start_list();
        match drv.step(None) {
            Action::SendCommand { packet, .. } => assert_eq!(packet, wrap_egui_frame(&CMD_LIST)),
            other => panic!("Unexpected {:?}", other),
        }

        let mut list_rsp = vec![0u8; EGISMOC_LIST_RESPONSE_PREFIX_SIZE];
        list_rsp[..8].copy_from_slice(&EGISMOC_READ_PREFIX);
        list_rsp.extend_from_slice(&id1);
        list_rsp.extend_from_slice(&[0x90, 0x00]);

        match drv.step(Some(&list_rsp)) {
            Action::TaskComplete(TaskResult::ListComplete { enrolled_ids }) => {
                assert_eq!(enrolled_ids, vec![id1]);
            }
            other => panic!("Unexpected {:?}", other),
        }

        // Delete flow
        drv.start_delete(id1);
        let _ = drv.step(None); // CMD_LIST
        match drv.step(Some(&list_rsp)) {
            Action::SendCommand { packet, .. } => {
                assert_eq!(packet, wrap_egui_frame(&build_delete_payload(&[id1])));
            }
            other => panic!("Unexpected {:?}", other),
        }

        let mut del_rsp = EGISMOC_READ_PREFIX.to_vec();
        del_rsp.extend_from_slice(&[0x00, 0x00]);
        del_rsp.extend_from_slice(&RSP_DELETE_SUCCESS_PREFIX);

        assert_eq!(
            drv.step(Some(&del_rsp)),
            Action::TaskComplete(TaskResult::DeleteComplete)
        );
    }

    #[test]
    fn test_identify_with_usb_reset_mac_mismatch_and_cancellation() {
        let mut drv = EgisMocDriver::from_pid(0x0582);
        // Simulamos sesión SDCP ya conectada mediante una carga de claim sintético
        let mut fake_claim = vec![0u8; 295];
        fake_claim[0..32].copy_from_slice(&[
            0x84, 0x00, 0xED, 0x14, 0x57, 0x9C, 0xDF, 0x11, 0x58, 0x64, 0x77, 0xE8, 0x36, 0xE8,
            0xCB, 0x52, 0x70, 0x84, 0x41, 0xC1, 0xC2, 0xA4, 0x47, 0xC2, 0x18, 0xC5, 0xBB, 0xC2,
            0xD1, 0x18, 0xFB, 0xC7,
        ]);
        fake_claim[32..97].copy_from_slice(&[
            0x04, 0x52, 0xF0, 0x56, 0xFF, 0xB9, 0xC6, 0x72, 0x86, 0x54, 0x77, 0x1A, 0x36, 0x29,
            0xB7, 0x70, 0x76, 0x7B, 0x19, 0xA2, 0x10, 0x6A, 0x49, 0x16, 0xFB, 0x81, 0xBA, 0x06,
            0xEF, 0x67, 0x97, 0xC4, 0xA3, 0xDF, 0x67, 0x2A, 0xDE, 0x0E, 0x91, 0x16, 0xD1, 0xAB,
            0xE2, 0x78, 0xA8, 0x22, 0x3A, 0xBD, 0xE4, 0x95, 0x8D, 0x62, 0xD4, 0xFF, 0x68, 0x82,
            0x15, 0x9F, 0x06, 0x17, 0xC6, 0xF8, 0xCE, 0x10, 0xBF,
        ]);
        // Inicializar sesión directamente usando set_host_keys y conectando con vector real
        drv.sdcp
            .set_host_keys(
                Some(fake_claim[0..32].try_into().unwrap()),
                Some(&[0x11u8; 32]),
            )
            .unwrap();
        // Forzamos is_connected mediante un claim temporal en disco con boot_id actual
        let boot_id =
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
        let mut claim_buf = Vec::new();
        claim_buf.extend_from_slice(&fake_claim[0..97]);
        claim_buf.extend_from_slice(&[0x22u8; 32 * 5]); // random + 4 secrets
        claim_buf.extend_from_slice(&[0u8; 7]);
        claim_buf.extend_from_slice(&1000i64.to_le_bytes());
        claim_buf.extend_from_slice(boot_id.as_bytes());
        claim_buf.push(0);
        claim_buf.extend_from_slice(&[0u8; 14]);
        let tmp_claim = std::env::temp_dir().join("egismoc_rs_unit_test_claim");
        std::fs::write(&tmp_claim, &claim_buf).unwrap();
        drv.sdcp.try_load_cached_claim(&tmp_claim).unwrap();
        let _ = std::fs::remove_file(&tmp_claim);

        let id1 = [0x77u8; 32];
        let mut list_rsp = vec![0u8; EGISMOC_LIST_RESPONSE_PREFIX_SIZE];
        list_rsp[..8].copy_from_slice(&EGISMOC_READ_PREFIX);
        list_rsp.extend_from_slice(&id1);
        list_rsp.extend_from_slice(&[0x90, 0x00]);

        // 1. Probar cancelación limpia en medio de espera de dedo
        drv.start_identify();
        let _ = drv.step(None); // CMD_LIST
        let _ = drv.step(Some(&list_rsp)); // CMD_SENSOR_RESET
        let _ = drv.step(Some(&make_ok_resp())); // CMD_SENSOR_IDENTIFY
        assert_eq!(
            drv.step(Some(&make_ok_resp())),
            Action::WaitFingerOnSensor {
                enroll_progress: None
            }
        );

        // Cancelamos mientras espera el dedo y reiniciamos inmediatamente sin panic/assert!
        drv.cancel();
        assert!(drv.task.is_none());
        assert_eq!(drv.step(None), Action::Idle);

        // 2. Reiniciar Identify y completar con tolerancia a reinicio USB (MacMismatchAfterReset)
        drv.start_identify();
        let _ = drv.step(None); // CMD_LIST
        let _ = drv.step(Some(&list_rsp)); // CMD_SENSOR_RESET
        let _ = drv.step(Some(&make_ok_resp())); // CMD_SENSOR_IDENTIFY
        let _ = drv.step(Some(&make_ok_resp())); // WaitFingerOnSensor
        let _ = drv.step(Some(&make_interrupt_finger_present())); // CMD_SENSOR_CHECK
        let _ = drv.step(Some(&make_ok_resp())); // CMD_CHECK

        // Respuesta con MAC de sesión volátil reiniciada pero enrollment_id válido en hardware
        let mut check_rsp = vec![0u8; EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE];
        check_rsp[..8].copy_from_slice(&EGISMOC_READ_PREFIX);
        check_rsp.extend_from_slice(&[0xDEu8; 32]); // MAC tras reset USB
        check_rsp.extend_from_slice(&id1); // enrollment_id coincidente
        check_rsp.extend_from_slice(&RSP_IDENTIFY_MATCH_SUFFIX);

        let _ = drv.step(Some(&check_rsp)); // CMD_SENSOR_RESET final
        match drv.step(Some(&make_ok_resp())) {
            Action::TaskComplete(TaskResult::IdentifyComplete {
                matched_enrollment_id,
                verification,
            }) => {
                assert_eq!(matched_enrollment_id, Some(id1));
                assert_eq!(
                    verification,
                    Some(IdentityVerification::MacMismatchAfterReset)
                );
            }
            other => panic!("Expected IdentifyComplete, got {:?}", other),
        }
    }

    #[test]
    fn test_enroll_full_state_machine() {
        let mut drv = EgisMocDriver::from_pid(0x0582);
        drv.max_enroll_stages = 2; // 2 etapas para test rápido de ciclo completo

        // Cargar sesión SDCP pre-inicializada
        let boot_id =
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
        let mut claim_buf = Vec::new();
        claim_buf.extend_from_slice(&[
            0x84, 0x00, 0xED, 0x14, 0x57, 0x9C, 0xDF, 0x11, 0x58, 0x64, 0x77, 0xE8, 0x36, 0xE8,
            0xCB, 0x52, 0x70, 0x84, 0x41, 0xC1, 0xC2, 0xA4, 0x47, 0xC2, 0x18, 0xC5, 0xBB, 0xC2,
            0xD1, 0x18, 0xFB, 0xC7,
        ]);
        claim_buf.extend_from_slice(&[
            0x04, 0x52, 0xF0, 0x56, 0xFF, 0xB9, 0xC6, 0x72, 0x86, 0x54, 0x77, 0x1A, 0x36, 0x29,
            0xB7, 0x70, 0x76, 0x7B, 0x19, 0xA2, 0x10, 0x6A, 0x49, 0x16, 0xFB, 0x81, 0xBA, 0x06,
            0xEF, 0x67, 0x97, 0xC4, 0xA3, 0xDF, 0x67, 0x2A, 0xDE, 0x0E, 0x91, 0x16, 0xD1, 0xAB,
            0xE2, 0x78, 0xA8, 0x22, 0x3A, 0xBD, 0xE4, 0x95, 0x8D, 0x62, 0xD4, 0xFF, 0x68, 0x82,
            0x15, 0x9F, 0x06, 0x17, 0xC6, 0xF8, 0xCE, 0x10, 0xBF,
        ]);
        claim_buf.extend_from_slice(&[
            0xD8, 0x77, 0x40, 0x3A, 0xBE, 0x82, 0xF4, 0xD9, 0x7E, 0x14, 0x48, 0xC5, 0x05, 0x2D,
            0x83, 0xA5, 0x32, 0xA4, 0x5E, 0x56, 0xEF, 0x04, 0x9C, 0xBB, 0xF9, 0x81, 0x13, 0x75,
            0x20, 0xE7, 0x13, 0xBF,
        ]);
        claim_buf.extend_from_slice(&[0x33u8; 32 * 4]);
        claim_buf.extend_from_slice(&[0u8; 7]);
        claim_buf.extend_from_slice(&1000i64.to_le_bytes());
        claim_buf.extend_from_slice(boot_id.as_bytes());
        claim_buf.push(0);
        claim_buf.extend_from_slice(&[0u8; 14]);
        let tmp_claim = std::env::temp_dir().join("egismoc_rs_unit_test_enroll_claim");
        std::fs::write(&tmp_claim, &claim_buf).unwrap();
        drv.sdcp.try_load_cached_claim(&tmp_claim).unwrap();
        let _ = std::fs::remove_file(&tmp_claim);

        drv.start_enroll();
        // Salto directo al estado post-SDCP connect para verificar el bucle de captura y commit
        drv.task = Some(TaskState::Enroll {
            step: EnrollStep::WaitEnrolledIds,
            stage: 0,
            enrollment_nonce: [0u8; 32],
            enrollment_id: [0u8; 32],
        });

        let empty_list = vec![0u8; EGISMOC_LIST_RESPONSE_PREFIX_SIZE + 2];
        let _ = drv.step(Some(&empty_list)); // CMD_SENSOR_RESET
        let _ = drv.step(Some(&make_ok_resp())); // CMD_SENSOR_ENROLL
        let _ = drv.step(Some(&make_ok_resp())); // WaitFingerOnSensor
        let _ = drv.step(Some(&make_interrupt_finger_present())); // CMD_SENSOR_CHECK
        let _ = drv.step(Some(&make_ok_resp())); // CMD_CHECK

        let mut not_enrolled_rsp = EGISMOC_READ_PREFIX.to_vec();
        not_enrolled_rsp.extend_from_slice(&[0, 0, 0, 0, 0x90, 0x04]);
        let _ = drv.step(Some(&not_enrolled_rsp)); // CMD_ENROLL_STARTING

        let mut enroll_starting_rsp = vec![0u8; EGISMOC_ENROLL_STARTING_RESPONSE_PREFIX_SIZE];
        enroll_starting_rsp[..8].copy_from_slice(&EGISMOC_READ_PREFIX);
        enroll_starting_rsp.extend_from_slice(&[0xABu8; 32]); // device_nonce
        enroll_starting_rsp.extend_from_slice(&RSP_ENROLL_STARTING_SUFFIX);

        let _ = drv.step(Some(&enroll_starting_rsp)); // Capture 1: CMD_SENSOR_RESET
        let _ = drv.step(Some(&make_ok_resp())); // Capture 1: CMD_SENSOR_START_CAPTURE
        let _ = drv.step(Some(&make_ok_resp())); // Capture 1: WaitFingerOnSensor
        let _ = drv.step(Some(&make_interrupt_finger_present())); // Capture 1: CMD_CAPTURE_POST_WAIT_FINGER
        let _ = drv.step(Some(&make_ok_resp())); // Capture 1: CMD_READ_CAPTURE

        let mut read_ok_rsp = EGISMOC_READ_PREFIX.to_vec();
        read_ok_rsp.extend_from_slice(&[0, 0, 0, 0]);
        read_ok_rsp.extend_from_slice(&RSP_READ_SUCCESS_SUFFIX);

        // Fin de etapa 1/2 -> emite progreso stage=1 y envía CMD_SENSOR_RESET
        match drv.step(Some(&read_ok_rsp)) {
            Action::SendCommand {
                enroll_progress: Some(prog),
                ..
            } => {
                assert_eq!(prog.completed_stages, 1);
                assert_eq!(prog.status, CaptureReadStatus::Success);
            }
            other => panic!("Unexpected {:?}", other),
        }

        // Etapa 2/2
        let _ = drv.step(Some(&make_ok_resp())); // CMD_SENSOR_START_CAPTURE
        let _ = drv.step(Some(&make_ok_resp())); // WaitFingerOnSensor
        let _ = drv.step(Some(&make_interrupt_finger_present())); // CMD_CAPTURE_POST_WAIT_FINGER
        let _ = drv.step(Some(&make_ok_resp())); // CMD_READ_CAPTURE

        // Fin de etapa 2/2 -> emite progreso stage=2 y envía CMD_COMMIT_STARTING
        match drv.step(Some(&read_ok_rsp)) {
            Action::SendCommand {
                packet,
                enroll_progress: Some(prog),
                ..
            } => {
                assert_eq!(prog.completed_stages, 2);
                assert_eq!(packet, wrap_egui_frame(&CMD_COMMIT_STARTING));
            }
            other => panic!("Unexpected {:?}", other),
        }

        let _ = drv.step(Some(&make_ok_resp())); // CMD_NEW_PRINT (ENROLL_COMMIT)
        let _ = drv.step(Some(&make_ok_resp())); // CMD_SENSOR_RESET (ENROLL_COMMIT_SENSOR_RESET)

        match drv.step(Some(&make_ok_resp())) {
            Action::TaskComplete(TaskResult::EnrollComplete { enrollment_id }) => {
                assert_ne!(enrollment_id, [0u8; 32]);
            }
            other => panic!("Expected EnrollComplete, got {:?}", other),
        }
    }
}
