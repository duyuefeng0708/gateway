#!/bin/sh
# Privacy Gateway installer
# Usage: curl -sSf https://gateway.dev/install | sh
#
# POSIX-compatible. No bash-isms.

set -e

# ── Colors (disabled when not a terminal or NO_COLOR is set) ────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  RED=''
  GREEN=''
  YELLOW=''
  BLUE=''
  BOLD=''
  RESET=''
fi

# ── Helper functions ────────────────────────────────────────────────────
info()    { printf "${BLUE}[info]${RESET}    %s\n" "$1"; }
success() { printf "${GREEN}[ok]${RESET}      %s\n" "$1"; }
warn()    { printf "${YELLOW}[warn]${RESET}    %s\n" "$1"; }
error()   { printf "${RED}[error]${RESET}   %s\n" "$1" >&2; }
step()    { printf "\n${BOLD}==> %s${RESET}\n" "$1"; }

die() {
  error "$1"
  exit 1
}

# ── Usage / help ────────────────────────────────────────────────────────
usage() {
  cat <<'USAGE'
Privacy Gateway Installer

Usage:
  curl -sSf https://gateway.dev/install | sh
  sh install.sh [OPTIONS]

Options:
  --help          Show this help message
  --docker-only   Skip binary install; set up Docker Compose only
  --prefix DIR    Install binary to DIR (default: /usr/local/bin or ~/.local/bin)
  --no-model      Skip pulling the Ollama model
  --yes           Skip confirmation prompts

Environment:
  NO_COLOR        Disable colored output
USAGE
  exit 0
}

# ── Parse flags ─────────────────────────────────────────────────────────
DOCKER_ONLY=0
SKIP_MODEL=0
AUTO_YES=0
CUSTOM_PREFIX=""

while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h)       usage ;;
    --docker-only)   DOCKER_ONLY=1 ;;
    --no-model)      SKIP_MODEL=1 ;;
    --yes|-y)        AUTO_YES=1 ;;
    --prefix)
      shift
      [ -z "${1:-}" ] && die "--prefix requires a directory argument"
      CUSTOM_PREFIX="$1"
      ;;
    *)
      warn "Unknown option: $1 (ignored)"
      ;;
  esac
  shift
done

# ── Detect OS and architecture ──────────────────────────────────────────
detect_env() {
  step "Detecting environment"

  OS="$(uname -s)"
  ARCH="$(uname -m)"
  IS_WSL=0

  # Normalise OS
  case "$OS" in
    Linux)
      if [ -f /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; then
        IS_WSL=1
        OS_LABEL="Linux (WSL)"
      else
        OS_LABEL="Linux"
      fi
      OS_TAG="linux"
      ;;
    Darwin)
      OS_LABEL="macOS"
      OS_TAG="darwin"
      ;;
    *)
      die "Unsupported operating system: $OS"
      ;;
  esac

  # Normalise architecture
  case "$ARCH" in
    x86_64|amd64)
      ARCH_TAG="amd64"
      ARCH_LABEL="x86_64"
      ;;
    aarch64|arm64)
      ARCH_TAG="arm64"
      ARCH_LABEL="aarch64/arm64"
      ;;
    *)
      die "Unsupported architecture: $ARCH"
      ;;
  esac

  info "OS:   $OS_LABEL"
  info "Arch: $ARCH_LABEL"

  # GPU detection (best-effort)
  HAS_GPU=0
  if command -v nvidia-smi >/dev/null 2>&1; then
    if nvidia-smi >/dev/null 2>&1; then
      HAS_GPU=1
      success "NVIDIA GPU detected"
    fi
  fi

  if [ "$HAS_GPU" -eq 0 ]; then
    warn "No GPU detected -- Ollama inference will run on CPU (slower but functional)"
  fi
}

# ── Check prerequisites ─────────────────────────────────────────────────
check_prerequisites() {
  step "Checking prerequisites"

  # curl or wget
  DOWNLOAD_CMD=""
  if command -v curl >/dev/null 2>&1; then
    DOWNLOAD_CMD="curl"
    success "curl found"
  elif command -v wget >/dev/null 2>&1; then
    DOWNLOAD_CMD="wget"
    success "wget found"
  else
    die "Neither curl nor wget found. Please install one and retry."
  fi

  # Docker (required for Ollama sidecar)
  if command -v docker >/dev/null 2>&1; then
    DOCKER_VERSION="$(docker --version 2>/dev/null || true)"
    success "Docker found: $DOCKER_VERSION"

    # Verify the daemon is reachable
    if ! docker info >/dev/null 2>&1; then
      warn "Docker daemon is not running or current user lacks permission."
      warn "Start Docker and/or add your user to the docker group, then re-run."
    fi
  else
    error "Docker is required but not installed."
    printf "\n"
    info "Install Docker:"
    case "$OS_TAG" in
      linux)
        info "  curl -fsSL https://get.docker.com | sh"
        info "  sudo usermod -aG docker \$USER"
        ;;
      darwin)
        info "  brew install --cask docker"
        info "  Or download from https://www.docker.com/products/docker-desktop"
        ;;
    esac
    printf "\n"
    die "Please install Docker and re-run this installer."
  fi
}

# ── Download helper ─────────────────────────────────────────────────────
download() {
  # $1 = URL, $2 = output path
  case "$DOWNLOAD_CMD" in
    curl)
      curl -fSL --progress-bar -o "$2" "$1"
      ;;
    wget)
      wget --show-progress -q -O "$2" "$1"
      ;;
  esac
}

# ── Determine install prefix ───────────────────────────────────────────
resolve_prefix() {
  if [ -n "$CUSTOM_PREFIX" ]; then
    INSTALL_DIR="$CUSTOM_PREFIX"
    return
  fi

  # Default: /usr/local/bin if writable, else ~/.local/bin
  if [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
  elif [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="$HOME/.local/bin"
  fi
}

# ── Install binary ──────────────────────────────────────────────────────
install_binary() {
  step "Installing gateway-proxy binary"

  resolve_prefix

  BINARY_NAME="gateway-proxy-${OS_TAG}-${ARCH_TAG}"
  RELEASE_URL="https://github.com/motiful/gateway/releases/latest/download/${BINARY_NAME}"

  info "Download URL: $RELEASE_URL"
  info "Install to:   $INSTALL_DIR/gateway-proxy"

  # Confirm non-default location
  if [ "$INSTALL_DIR" != "/usr/local/bin" ] && [ "$AUTO_YES" -eq 0 ]; then
    printf "${YELLOW}Install to %s? [Y/n]${RESET} " "$INSTALL_DIR"
    read -r REPLY < /dev/tty 2>/dev/null || REPLY="y"
    case "$REPLY" in
      [nN]*) die "Installation cancelled." ;;
    esac
  fi

  mkdir -p "$INSTALL_DIR"

  TMPFILE="$(mktemp)"
  trap 'rm -f "$TMPFILE"' EXIT

  info "Downloading gateway-proxy..."
  if download "$RELEASE_URL" "$TMPFILE"; then
    chmod +x "$TMPFILE"

    # Move into place (use sudo if needed)
    if [ -w "$INSTALL_DIR" ]; then
      mv "$TMPFILE" "$INSTALL_DIR/gateway-proxy"
    else
      info "Elevated permissions required to install to $INSTALL_DIR"
      sudo mv "$TMPFILE" "$INSTALL_DIR/gateway-proxy"
    fi

    success "Binary installed to $INSTALL_DIR/gateway-proxy"

    # Check PATH
    case ":$PATH:" in
      *":$INSTALL_DIR:"*) ;;
      *)
        warn "$INSTALL_DIR is not in your PATH."
        info "Add it:  export PATH=\"$INSTALL_DIR:\$PATH\""
        ;;
    esac
  else
    warn "Binary download failed -- falling back to Docker image approach."
    warn "You can run the gateway via Docker Compose instead."
    DOCKER_ONLY=1
  fi
}

# ── Docker Compose setup ────────────────────────────────────────────────
setup_docker_compose() {
  step "Setting up Docker Compose"

  CONFIG_DIR="$HOME/.config/gateway"
  mkdir -p "$CONFIG_DIR"

  COMPOSE_URL="https://raw.githubusercontent.com/motiful/gateway/main/docker-compose.yml"
  COMPOSE_FILE="$CONFIG_DIR/docker-compose.yml"

  info "Downloading docker-compose.yml..."
  if download "$COMPOSE_URL" "$COMPOSE_FILE"; then
    success "Docker Compose file saved to $COMPOSE_FILE"
  else
    warn "Could not download docker-compose.yml (network error)"
    info "You can grab it later:"
    info "  curl -o docker-compose.yml $COMPOSE_URL"
  fi
}

# ── Pull Ollama model ───────────────────────────────────────────────────
pull_ollama_model() {
  step "Setting up Ollama and PII detection model"

  # Start Ollama container if not already running
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^gateway-ollama$'; then
    success "Ollama container (gateway-ollama) is already running"
  else
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^gateway-ollama$'; then
      info "Starting existing gateway-ollama container..."
      docker start gateway-ollama
    else
      info "Starting Ollama container..."
      docker run -d --name gateway-ollama -p 11434:11434 ollama/ollama
    fi

    # Wait for Ollama to be ready
    info "Waiting for Ollama to start..."
    TRIES=0
    while [ "$TRIES" -lt 30 ]; do
      if docker exec gateway-ollama ollama list >/dev/null 2>&1; then
        break
      fi
      TRIES=$((TRIES + 1))
      sleep 1
    done

    if [ "$TRIES" -ge 30 ]; then
      warn "Ollama container did not become ready in time."
      warn "You can pull the model manually later:"
      info "  docker exec gateway-ollama ollama pull MTBS/anonymizer"
      return
    fi

    success "Ollama container is running"
  fi

  info "Pulling PII detection model (MTBS/anonymizer)..."
  info "This may take a few minutes depending on your connection."
  if docker exec gateway-ollama ollama pull MTBS/anonymizer; then
    success "Model MTBS/anonymizer pulled successfully"
  else
    warn "Model pull failed. You can retry later:"
    info "  docker exec gateway-ollama ollama pull MTBS/anonymizer"
  fi
}

# ── Create default config ───────────────────────────────────────────────
create_default_config() {
  step "Creating default configuration"

  CONFIG_DIR="$HOME/.config/gateway"
  ENV_FILE="$CONFIG_DIR/.env"

  mkdir -p "$CONFIG_DIR"

  if [ -f "$ENV_FILE" ]; then
    info "Config already exists at $ENV_FILE -- skipping (will not overwrite)"
    return
  fi

  cat > "$ENV_FILE" <<'ENVEOF'
GATEWAY_LISTEN=127.0.0.1:8443
GATEWAY_UPSTREAM=https://api.anthropic.com
GATEWAY_OLLAMA_URL=http://localhost:11434
GATEWAY_SCAN_MODE=fast
# Set your API key:
# ANTHROPIC_API_KEY=your-key-here
ENVEOF

  success "Default config written to $ENV_FILE"
}

# ── Print getting-started instructions ──────────────────────────────────
print_instructions() {
  printf "\n"
  printf "${GREEN}${BOLD}Gateway installed successfully!${RESET}\n"
  printf "\n"
  printf "${BOLD}Quick start:${RESET}\n"

  if [ "$DOCKER_ONLY" -eq 0 ]; then
    printf "  1. Set your API key:       ${BLUE}export ANTHROPIC_API_KEY=your-key-here${RESET}\n"
    printf "  2. Start the gateway:      ${BLUE}gateway-proxy${RESET}\n"
    printf "  3. Configure your client:  ${BLUE}export HTTPS_PROXY=http://127.0.0.1:8443${RESET}\n"
    printf "\n"
    printf "${BOLD}Or use Docker Compose:${RESET}\n"
  fi

  printf "  ${BLUE}curl -O https://raw.githubusercontent.com/motiful/gateway/main/docker-compose.yml${RESET}\n"
  printf "  ${BLUE}ANTHROPIC_API_KEY=your-key docker compose up${RESET}\n"

  printf "\n"
  printf "${BOLD}Config:${RESET}  %s\n" "$HOME/.config/gateway/.env"

  if [ "$DOCKER_ONLY" -eq 0 ] && [ -n "${INSTALL_DIR:-}" ]; then
    printf "${BOLD}Binary:${RESET}  %s/gateway-proxy\n" "$INSTALL_DIR"
  fi

  printf "\n"
  printf "Docs:    https://github.com/motiful/gateway\n"
  printf "\n"
}

# ── Main ────────────────────────────────────────────────────────────────
main() {
  printf "\n"
  printf "${BOLD}Privacy Gateway Installer${RESET}\n"
  printf "─────────────────────────\n"

  detect_env
  check_prerequisites

  if [ "$DOCKER_ONLY" -eq 1 ]; then
    setup_docker_compose
  else
    install_binary
  fi

  if [ "$SKIP_MODEL" -eq 0 ]; then
    pull_ollama_model
  fi

  create_default_config
  print_instructions
}

main
