#!/usr/bin/env bash
set -euo pipefail

C_DRIVER_PKG="$(ls -t /home/ishiro/.gemini/antigravity/brain/8e8b06ae-cfed-4f88-9f56-98a1f9a032e2/scratch/build_fix/libfprint-egismoc-sdcp-git/libfprint-egismoc-sdcp-git-*.pkg.tar.zst 2>/dev/null | head -n1 || true)"

if [[ -n "${C_DRIVER_PKG}" && -f "${C_DRIVER_PKG}" ]]; then
  echo "==> Restaurando paquete C SDCP parcheado: $(basename "${C_DRIVER_PKG}")"
  sudo pacman -U --ask 4 --noconfirm "${C_DRIVER_PKG}"
else
  echo "==> Paquete C SDCP local no encontrado; reinstalando libfprint desde repositorios..."
  sudo pacman -S --ask 4 --noconfirm libfprint
fi

echo "==> Reiniciando fprintd.service..."
sudo systemctl restart fprintd.service

echo "==> Driver en C restaurado correctamente."
