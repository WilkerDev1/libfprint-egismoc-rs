# Maintainer: WilkerDev1 <capellancoronadowilker@gmail.com>
# Based on libfprint-egismoc-sdcp-git (TenSeventy7 / Joshua Grisham)
#
# Replaces the entire C egismoc driver (~4,455 LoC) with 100% pure Rust:
# - egismoc-core (Rust staticlib: Sans-I/O state machine, EGIS/SIGE framing,
#   Microsoft SDCP, and native Rust GObject + FpiUsbTransfer adapter — 0 lines of C)

pkgname=libfprint-egismoc-rs-git
pkgver=r1831.4d128d4
pkgrel=4
pkgdesc="Library for fingerprint readers with 100% Rust SDCP & USB/GObject driver for EgisTec egismoc sensors (1c7a:0582 - 1c7a:05a5)"
url="https://github.com/WilkerDev1/libfprint-egismoc-rs"
arch=(x86_64)
license=(LGPL-2.1-or-later)
depends=(
  gcc-libs
  glib2
  glibc
  libgudev
  libgusb
  openssl
  pixman
)
makedepends=(
  git
  glib2-devel
  gobject-introspection
  meson
)
checkdepends=(
  cairo
  umockdev
)
provides=(
  "libfprint=1.94.100"
  "libfprint-2.so=2-64"
)
conflicts=(libfprint libfprint-egismoc-sdcp-git)
replaces=(libfprint-egismoc-sdcp-git)
groups=(fprint)
source=()
sha256sums=()

pkgver() {
  cd "${startdir}/libfprint-egismoc-sdcp"
  printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
  export PATH="${HOME}/.cargo/bin:${PATH}"

  msg2 "Building pure-Rust egismoc-core staticlib (SDCP + Sans-I/O + GObject/USB adapter)..."
  cd "${startdir}/egismoc-core"
  cargo build --release --locked

  cd "${startdir}"
  rm -rf pkg_build
  local meson_options=(
    -D drivers=egismoc
    -D doc=false
    -D gtk-examples=false
    -D installed-tests=false
  )

  arch-meson "${startdir}/libfprint-egismoc-sdcp" pkg_build "${meson_options[@]}"
  meson compile -C pkg_build
}

check() {
  export PATH="${HOME}/.cargo/bin:${PATH}"

  msg2 "Running Rust unit tests & strict clippy (cargo test)..."
  (cd "${startdir}/egismoc-core" && cargo test --locked)

  msg2 "Running libfprint + umockdev integration tests (meson test)..."
  meson test -C "${startdir}/pkg_build" --print-errorlogs
}

package() {
  meson install -C "${startdir}/pkg_build" --destdir "${pkgdir}"

  install -Dm644 "${startdir}/system/71-egismoc-no-autosuspend.rules" \
    "${pkgdir}/usr/lib/udev/rules.d/71-egismoc-no-autosuspend.rules"
  install -Dm644 "${startdir}/system/90-egismoc-restart-fprintd.hook" \
    "${pkgdir}/usr/share/libalpm/hooks/90-egismoc-restart-fprintd.hook"
}
