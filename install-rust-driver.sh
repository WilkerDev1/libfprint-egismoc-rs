#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_FILE="$(ls -t "${SCRIPT_DIR}"/libfprint-egismoc-rs-git-*.pkg.tar.zst 2>/dev/null | head -n1 || true)"

if [[ -z "${PKG_FILE}" ]]; then
  echo "Error: No se encontró el paquete libfprint-egismoc-rs-git-*.pkg.tar.zst en ${SCRIPT_DIR}" >&2
  exit 1
fi

echo "==> Instalando driver híbrido Rust+C: $(basename "${PKG_FILE}")"
sudo pacman -U --ask 4 --noconfirm "${PKG_FILE}"

echo "==> Reiniciando fprintd.service..."
sudo systemctl restart fprintd.service

echo "==> Listo. Puedes probar el lector con: fprintd-verify o fprintd-list \$USER"
