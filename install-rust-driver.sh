#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_USER="${SUDO_USER:-$USER}"
PKG_FILE="$(ls -t "${SCRIPT_DIR}"/libfprint-egismoc-rs-git-*.pkg.tar.zst 2>/dev/null | head -n1 || true)"

if [[ -z "${PKG_FILE}" ]]; then
  echo "Error: No se encontró el paquete libfprint-egismoc-rs-git-*.pkg.tar.zst en ${SCRIPT_DIR}" >&2
  echo "Compílalo primero con: makepkg -f" >&2
  exit 1
fi

run_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

echo "==> [1/5] Instalando driver 100% Rust: $(basename "${PKG_FILE}")"
run_root pacman -U --ask 4 --noconfirm "${PKG_FILE}"

echo "==> [2/5] Protegiendo el driver en /etc/pacman.conf (IgnorePkg = libfprint)..."
run_root python3 - <<'PYEOF'
from pathlib import Path
import re

conf_path = Path("/etc/pacman.conf")
text = conf_path.read_text(encoding="utf-8")

# Comprobar si libfprint ya está ignorado en una línea IgnorePkg activa
active_match = re.search(r"(?m)^IgnorePkg\s*=\s*(.*)$", text)
if active_match:
    pkgs = active_match.group(1).split()
    if "libfprint" not in pkgs:
        new_line = f"IgnorePkg   = {' '.join(pkgs + ['libfprint'])}"
        text = text[:active_match.start()] + new_line + text[active_match.end():]
        conf_path.write_text(text, encoding="utf-8")
        print("  -> Añadido 'libfprint' a la línea IgnorePkg existente.")
    else:
        print("  -> 'libfprint' ya estaba protegido en IgnorePkg.")
else:
    # Descomentar la primera línea #IgnorePkg dentro de [options] o insertarla tras [options]
    commented = re.search(r"(?m)^#IgnorePkg\s*=.*$", text)
    if commented:
        text = text[:commented.start()] + "IgnorePkg   = libfprint" + text[commented.end():]
    else:
        text = re.sub(r"(?m)^\[options\]\s*$", "[options]\nIgnorePkg   = libfprint", text, count=1)
    conf_path.write_text(text, encoding="utf-8")
    print("  -> Configurado 'IgnorePkg = libfprint' en /etc/pacman.conf.")
PYEOF

echo "==> [3/5] Configurando PAM persistente para Polkit y sudo..."
run_root install -Dm644 /dev/stdin /etc/pam.d/polkit-1 <<'EOF'
#%PAM-1.0

auth       sufficient   pam_fprintd.so max-tries=3 timeout=10
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    include      system-auth
EOF

run_root install -Dm644 /dev/stdin /etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth      sufficient    pam_fprintd.so max-tries=3 timeout=10
auth      include       system-auth
account   include       system-auth
session   include       system-auth
session   optional      pam_systemd.so class=none
EOF

if [[ -f /etc/pam.d/sudo.pacnew ]]; then
  run_root rm -f /etc/pam.d/sudo.pacnew
  echo "  -> Fusionado y eliminado /etc/pam.d/sudo.pacnew."
fi

echo "==> [4/5] Recargando reglas udev (desactivando USB autosuspend en 1c7a:0582-05a5)..."
run_root udevadm control --reload-rules
run_root udevadm trigger --subsystem-match=usb --attr-match=idVendor=1c7a || true

for dev in /sys/bus/usb/devices/*; do
  if [[ -f "${dev}/idVendor" && "$(cat "${dev}/idVendor")" == "1c7a" ]]; then
    echo "on" | run_root tee "${dev}/power/control" >/dev/null
    echo "-1" | run_root tee "${dev}/power/autosuspend" >/dev/null || true
    echo "  -> $(basename "${dev}") ($(cat "${dev}/idVendor"):$(cat "${dev}/idProduct")): power/control=$(cat "${dev}/power/control")"
  fi
done

echo "==> [5/5] Reiniciando fprintd.service y verificando..."
run_root systemctl restart fprintd.service
sleep 1
fprintd-list "${TARGET_USER}" || true

echo ""
echo "==> ¡Listo! Si aparece 'has no fingers enrolled', registra tus huellas con:"
echo "    fprintd-enroll"
echo "    y pruébalo con: fprintd-verify"
