pkgname=inkspire-git
pkgver=1.0.0
pkgrel=1
pkgdesc="Fast OSINT and Port Scanner with CVE detection"
arch=('x86_64' 'aarch64')
url="https://github.com/VentieRavelle/Inkspire"
license=('MIT')
depends=('go')
makedepends=('git')
provides=('inkspire')
source=("git+${url}.git")
md5sums=('SKIP')

build() {
  cd "$srcdir/Inkspire/cmd"
  go build -o inkspire main.go
}

package() {
  install -Dm755 "$srcdir/Inkspire/cmd/inkspire" "$pkgdir/usr/bin/inkspire"
  install -Dm644 "$srcdir/Inkspire/data/known_ports.json" "$pkgdir/usr/share/inkspire/known_ports.json"
}