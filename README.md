# ========================================================================
#           LUPHAHLA HOST SCAN - INSTALLATION GUIDE
#               (WSL / Linux / macOS / Termux)
# ========================================================================

# --- IMPORTANT NOTES ---
# • All commands assume you have a working internet connection.
# • For macOS, Homebrew (https://brew.sh) is required.
# • For Termux, grant storage permissions if needed (termux-setup-storage).
# • The 'iproute2' package is Linux-specific; macOS and Termux users may skip it.


# ============================
#  1.  WINDOWS (WSL)
# ============================

# 1. Restart your computer if Windows asks you to.

# 2. Open your installed Linux distribution (e.g., Ubuntu) from Start.

# 3. Update system & install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y git bash openssl coreutils iproute2

# 4. Clone, enter, and set permissions
git clone https://github.com/loyisoluphahla/luphahla-host-scan.git
cd luphahla-host-scan
chmod +x auto-verify.sh verify.sh

# 5. Run
./auto-verify.sh

# 6. Syntax check (optional)
bash -n auto-verify.sh && bash -n verify.sh


# ============================
#  2.  LINUX (Debian / Ubuntu)
# ============================

sudo apt update && sudo apt upgrade -y
sudo apt install -y git bash openssl coreutils iproute2

git clone https://github.com/loyisoluphahla/luphahla-host-scan.git
cd luphahla-host-scan
chmod +x auto-verify.sh verify.sh
./auto-verify.sh
bash -n auto-verify.sh && bash -n verify.sh


# ============================
#  3.  LINUX (Fedora / RHEL / CentOS)
# ============================

sudo dnf update -y               # or 'sudo yum update -y'
sudo dnf install -y git bash openssl coreutils iproute2

git clone https://github.com/loyisoluphahla/luphahla-host-scan.git
cd luphahla-host-scan
chmod +x auto-verify.sh verify.sh
./auto-verify.sh
bash -n auto-verify.sh && bash -n verify.sh


# ============================
#  4.  macOS (with Homebrew)
# ============================

# Install Homebrew if not already installed:
# /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew update
brew install git bash openssl coreutils
# Note: iproute2 is not available on macOS – the script will use system tools.

git clone https://github.com/loyisoluphahla/luphahla-host-scan.git
cd luphahla-host-scan
chmod +x auto-verify.sh verify.sh
./auto-verify.sh
bash -n auto-verify.sh && bash -n verify.sh


# ============================
#  5.  ANDROID (Termux)
# ============================

# Update Termux packages
pkg update && pkg upgrade -y

# Install dependencies (iproute2 may not be available; install if found)
pkg install -y git bash openssl coreutils
pkg install -y iproute2 2>/dev/null || echo "iproute2 not available – skipping."

# Clone and set up
git clone https://github.com/loyisoluphahla/luphahla-host-scan.git
cd luphahla-host-scan
chmod +x auto-verify.sh verify.sh
./auto-verify.sh
bash -n auto-verify.sh && bash -n verify.sh


# ========================================================================
#  UPDATING AN EXISTING INSTALLATION (ALL PLATFORMS)
# ========================================================================

cd ~/luphahla-host-scan
git pull
chmod +x auto-verify.sh verify.sh
./auto-verify.sh

# ========================================================================
