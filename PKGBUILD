# Maintainer: ishiro (Experimental Level 3 Rust + C hybrid driver)
# Based on libfprint-egismoc-sdcp-git (TenSeventy7 / Joshua Grisham)
#
# Replaces the 2,234-line C egismoc driver + FpiSsm state machine with:
# - egismoc-core (Rust staticlib: Sans-I/O state machine, protocol framing, and Microsoft SDCP)
# - c-bridge/egismoc.c (Minimalist GObject/FpiUsbTransfer bridge)

pkgname=libfprint-egismoc-rs-git
pkgver=r1831.4d128d4
pkgrel=1
pkgdesc="Library for fingerprint readers with Rust Sans-I/O SDCP driver for EgisTec egismoc sensors (1c7a:0582 - 1c7a:05a5)"
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
provides=(libfprint libfprint-2.so)
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

  msg2 "Building egismoc-core Rust staticlib..."
  cd "${startdir}/egismoc-core"
  cargo build --release

  msg2 "Synchronizing C bridge and Rust header into libfprint tree..."
  cp -f "${startdir}/c-bridge/egismoc.c" \
        "${startdir}/c-bridge/egismoc.h" \
        "${startdir}/egismoc-core/include/egismoc_rs.h" \
        "${startdir}/libfprint-egismoc-sdcp/libfprint/drivers/egismoc/"

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

  msg2 "Running Rust unit tests (cargo test)..."
  (cd "${startdir}/egismoc-core" && cargo test)

  msg2 "Running libfprint + umockdev integration tests (meson test)..."
  meson test -C "${startdir}/pkg_build" --print-errorlogs
}

package() {
  meson install -C "${startdir}/pkg_build" --destdir "${pkgdir}"
}
