# Luphahla Host Scan

A multi-platform host scanning tool written in Bash.

## Installation

### Prerequisites
- **Internet connection**
- **macOS:** [Homebrew](https://brew.sh) required
- **Termux:** Run `termux-setup-storage` (optional)

---

### 1. Windows (WSL)
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git bash openssl coreutils iproute2

git clone https://github.com/loyisoluphahla/luphahla-host-scan.git
cd luphahla-host-scan
chmod +x auto-verify.sh verify.sh
./auto-verify.sh
Linux (Debian/Ubuntu)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git bash openssl coreutils iproute2

git clone https://github.com/loyisoluphahla/luphahla-host-scan.git
cd luphahla-host-scan
chmod +x auto-verify.sh verify.sh
./auto-verify.sh
```

3. Linux (Fedora/RHEL/CentOS)

```bash
sudo dnf update -y   # or 'sudo yum update -y'
sudo dnf install -y git bash openssl coreutils iproute2

git clone https://github.com/loyisoluphahla/luphahla-host-scan.git
cd luphahla-host-scan
chmod +x auto-verify.sh verify.sh
./auto-verify.sh
```

4. macOS (Homebrew)

```bash
brew update
brew install git bash openssl coreutils
# iproute2 is not available on macOS – script uses system tools.

git clone https://github.com/loyisoluphahla/luphahla-host-scan.git
cd luphahla-host-scan
chmod +x auto-verify.sh verify.sh
./auto-verify.sh
```

5. Android (Termux)

```bash
pkg update && pkg upgrade -y
pkg install -y git bash openssl coreutils
pkg install -y iproute2 2>/dev/null || echo "iproute2 skipped"

git clone https://github.com/loyisoluphahla/luphahla-host-scan.git
cd luphahla-host-scan
chmod +x auto-verify.sh verify.sh
./auto-verify.sh
```

---

Updating (All Platforms)

```bash
cd ~/luphahla-host-scan
git pull
chmod +x auto-verify.sh verify.sh
./auto-verify.sh
```

Verification

Run a syntax check to confirm the scripts are valid:

```bash
bash -n auto-verify.sh && bash -n verify.sh
```

(No output = all good)
