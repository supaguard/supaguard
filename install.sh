#!/usr/bin/env bash
# ==============================================================================
#  SupaGuard Universal Installer
#  One-line installation for macOS, Linux, and WSL environments.
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/supaguard/supaguard/main/install.sh | bash
#    wget -qO- https://raw.githubusercontent.com/supaguard/supaguard/main/install.sh | bash
# ==============================================================================

set -e

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[92m"
YELLOW="\033[93m"
CYAN="\033[96m"
RED="\033[91m"
MAGENTA="\033[95m"

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "   ███████╗██╗   ██╗██████╗  █████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
    echo "   ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
    echo "   ███████╗██║   ██║██████╔╝███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
    echo "   ╚════██║██║   ██║██╔═══╝ ██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
    echo "   ███████║╚██████╔╝██║     ██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
    echo "   ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    echo -e "${RESET}"
    echo -e "   ${BOLD}100% Security Suite & Multi-Layer Developer Defense${RESET}\n"
}

print_banner

echo -e "${CYAN}==> Initializing SupaGuard Installer...${RESET}\n"

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Python 3 is required to run SupaGuard.${RESET}"
    echo "Please install Python 3 (e.g., brew install python3 or apt install python3) and retry."
    exit 1
fi

INSTALL_DIR="$HOME/.supaguard/core"
BIN_DIR="$HOME/.local/bin"

if [ -w "/usr/local/bin" ]; then
    BIN_DIR="/usr/local/bin"
fi

mkdir -p "$INSTALL_DIR"
mkdir -p "$HOME/.local/bin"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -d "$SCRIPT_DIR/supaguard" ]; then
    echo -e " - Copying local SupaGuard source files..."
    cp -R "$SCRIPT_DIR/supaguard" "$INSTALL_DIR/"
    cp -R "$SCRIPT_DIR/bin" "$INSTALL_DIR/"
else
    echo -e " - Downloading latest SupaGuard release..."
    TMP_TAR="/tmp/supaguard_latest.tar.gz"
    curl -fsSL "https://github.com/supaguard/supaguard/archive/refs/heads/main.tar.gz" -o "$TMP_TAR" || \
    wget -q "https://github.com/supaguard/supaguard/archive/refs/heads/main.tar.gz" -O "$TMP_TAR"
    
    tar -xzf "$TMP_TAR" -C "/tmp/"
    cp -R /tmp/supaguard-main/supaguard "$INSTALL_DIR/"
    cp -R /tmp/supaguard-main/bin "$INSTALL_DIR/"
    rm -rf "$TMP_TAR" /tmp/supaguard-main
fi

cat << 'LAUNCHER' > "$BIN_DIR/supaguard"
#!/usr/bin/env python3
import sys
from pathlib import Path

core_dir = Path.home() / ".supaguard" / "core"
sys.path.insert(0, str(core_dir))

from supaguard.cli import main

if __name__ == "__main__":
    main()
LAUNCHER

chmod +x "$BIN_DIR/supaguard"
chmod +x "$INSTALL_DIR/bin/supaguard" 2>/dev/null || true

ln -sf "$BIN_DIR/supaguard" "$HOME/.local/bin/supaguard" 2>/dev/null || true

echo -e "\n${GREEN}${BOLD}[OK] SupaGuard successfully installed to:${RESET} $BIN_DIR/supaguard\n"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo -e "${YELLOW}[NOTE] '$BIN_DIR' is not in your current PATH.${RESET}"
    echo "Add the following line to your ~/.zshrc or ~/.bashrc:"
    echo -e "${CYAN}export PATH=\"$BIN_DIR:\$PATH\"${RESET}\n"
fi

echo -e "${CYAN}==> Verifying security engines...${RESET}"
"$BIN_DIR/supaguard" doctor

echo -e "${GREEN}${BOLD}Installation Complete!${RESET}"
echo -e "To scan your project:      ${CYAN}supaguard scan .${RESET}"
echo -e "To install Git hooks:      ${CYAN}supaguard hook install .${RESET}"
echo -e "To inspect supply chain:   ${CYAN}supaguard safe-install <pkg>${RESET}"
echo -e "To run real-time shield:   ${CYAN}supaguard watch . --daemon${RESET}\n"
