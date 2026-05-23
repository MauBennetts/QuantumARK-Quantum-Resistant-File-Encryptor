#!/usr/bin/env bash
# =============================================================
#   BlackPrism v4.0 — Script de Instalación de Dependencias
#   Soporta: macOS, Ubuntu/Debian, Fedora/RHEL, Arch Linux
# =============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {
  echo ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}${BOLD}║       BlackPrism v4.0 — Setup Script         ║${NC}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════╝${NC}"
  echo ""
}

ok()   { echo -e "  ${GREEN}✅ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; }
info() { echo -e "  ${CYAN}ℹ️  $1${NC}"; }
err()  { echo -e "  ${RED}❌ $1${NC}"; exit 1; }
step() { echo -e "\n${BOLD}▶ $1${NC}"; }

# ── Detectar OS ──────────────────────────────────────────────
detect_os() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
  elif [[ -f /etc/debian_version ]]; then
    OS="debian"
  elif [[ -f /etc/fedora-release ]] || [[ -f /etc/redhat-release ]]; then
    OS="fedora"
  elif [[ -f /etc/arch-release ]]; then
    OS="arch"
  else
    OS="unknown"
  fi
}

# ── Instalar Rust ────────────────────────────────────────────
install_rust() {
  step "Instalando Rust (rustup)"
  if command -v rustup &>/dev/null; then
    ok "Rust ya está instalado: $(rustc --version)"
    info "Actualizando Rust a la versión más reciente..."
    rustup update stable
  else
    info "Descargando rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
    ok "Rust instalado: $(rustc --version)"
  fi
}

# ── macOS ────────────────────────────────────────────────────
setup_macos() {
  step "Configurando dependencias para macOS"

  # Homebrew
  if ! command -v brew &>/dev/null; then
    info "Instalando Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  else
    ok "Homebrew ya instalado"
  fi

  # Xcode Command Line Tools
  if ! xcode-select -p &>/dev/null; then
    info "Instalando Xcode Command Line Tools..."
    xcode-select --install
    echo "  Espera a que termine la instalación y vuelve a ejecutar este script."
    exit 0
  else
    ok "Xcode CLT ya instalado"
  fi

  # WebKit (incluido en macOS por defecto con Tauri)
  ok "WebKit disponible (incluido en macOS)"

  install_rust

  ok "macOS listo para compilar BlackPrism"
}

# ── Ubuntu / Debian ──────────────────────────────────────────
setup_debian() {
  step "Configurando dependencias para Ubuntu/Debian"

  info "Actualizando repositorios..."
  sudo apt-get update -qq

  info "Instalando dependencias del sistema..."
  sudo apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    pkg-config \
    libssl-dev \
    libgtk-3-dev \
    libwebkit2gtk-4.1-dev \
    libappindicator3-dev \
    librsvg2-dev \
    patchelf \
    libayatana-appindicator3-dev

  ok "Dependencias del sistema instaladas"

  install_rust

  ok "Ubuntu/Debian listo para compilar BlackPrism"
}

# ── Fedora / RHEL / CentOS ───────────────────────────────────
setup_fedora() {
  step "Configurando dependencias para Fedora/RHEL"

  info "Instalando dependencias del sistema..."
  sudo dnf install -y \
    gcc \
    gcc-c++ \
    make \
    curl \
    wget \
    git \
    pkg-config \
    openssl-devel \
    gtk3-devel \
    webkit2gtk4.1-devel \
    librsvg2-devel \
    patchelf

  ok "Dependencias del sistema instaladas"

  install_rust

  ok "Fedora/RHEL listo para compilar BlackPrism"
}

# ── Arch Linux ───────────────────────────────────────────────
setup_arch() {
  step "Configurando dependencias para Arch Linux"

  info "Instalando dependencias del sistema..."
  sudo pacman -Sy --noconfirm \
    base-devel \
    curl \
    wget \
    git \
    pkgconf \
    openssl \
    gtk3 \
    webkit2gtk-4.1 \
    librsvg \
    patchelf

  ok "Dependencias del sistema instaladas"

  install_rust

  ok "Arch Linux listo para compilar BlackPrism"
}

# ── Compilar BlackPrism ──────────────────────────────────────
compile_app() {
  step "Compilando BlackPrism v4.0 en modo release..."

  if [[ ! -f "Cargo.toml" ]]; then
    err "Ejecuta este script desde la carpeta raíz del proyecto (donde está Cargo.toml)"
  fi

  source "$HOME/.cargo/env" 2>/dev/null || true

  cargo build --release

  ok "Compilación exitosa"

  BINARY="target/release/blackprism-tauri"
  if [[ -f "$BINARY" ]]; then
    echo ""
    info "Binario generado: $(pwd)/$BINARY"
    info "Tamaño: $(du -sh $BINARY | cut -f1)"
    echo ""
    echo -e "${GREEN}${BOLD}🎉 BlackPrism v4.0 compilado con éxito.${NC}"
    echo -e "   Para ejecutar:"
    echo -e "   ${CYAN}./target/release/blackprism-tauri${NC}"
  fi
}

# ── Main ─────────────────────────────────────────────────────
print_header
detect_os

info "Sistema detectado: $OS"

case "$OS" in
  macos)   setup_macos ;;
  debian)  setup_debian ;;
  fedora)  setup_fedora ;;
  arch)    setup_arch ;;
  unknown)
    warn "Sistema operativo no reconocido automáticamente."
    warn "Instala manualmente: Rust (rustup.rs) + libwebkit2gtk-4.1-dev + gtk3-dev"
    info "Luego ejecuta: cargo build --release"
    ;;
esac

# Preguntar si compilar ahora
echo ""
read -rp "  ¿Compilar BlackPrism ahora? [s/N]: " COMPILE
if [[ "$COMPILE" =~ ^[sS]$ ]]; then
  compile_app
else
  echo ""
  info "Para compilar manualmente más tarde:"
  echo -e "  ${CYAN}cargo build --release${NC}"
fi

echo ""
