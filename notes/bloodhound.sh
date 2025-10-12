#!/usr/bin/env bash
set -euo pipefail
# bloodhound_setup.sh
# Purpose: Fix PostgreSQL collation issues, install RustHound-CE, clone BloodHound.py
# Usage: ./bloodhound_setup.sh
# Note: BloodHound comes pre-installed with Kali Linux

# ---------- Config ----------
WORKDIR="$HOME/cptc/AD/BloodHound"
RUSTHOUND_DIR="$WORKDIR/rusthound"
BH_PY_DIR="$WORKDIR/BloodHound.py"

# ---------- Helpers ----------
info(){ echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
err(){ echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }

# ---------- Create working dir ----------
info "Creating working directory: $WORKDIR"
mkdir -p "$WORKDIR"

# ---------- Fix PostgreSQL Collation Version Mismatch ----------
info "Fixing PostgreSQL collation version mismatch..."
sudo systemctl start postgresql

# Fix collation versions for template databases
info "Refreshing collation versions for PostgreSQL databases..."
sudo -u postgres psql -c "ALTER DATABASE template0 REFRESH COLLATION VERSION;" 2>/dev/null || true
sudo -u postgres psql -c "ALTER DATABASE template1 REFRESH COLLATION VERSION;" 2>/dev/null || true
sudo -u postgres psql -c "ALTER DATABASE postgres REFRESH COLLATION VERSION;" 2>/dev/null || true

# Reindex system catalogs to prevent issues
info "Reindexing system catalogs..."
sudo -u postgres psql -d template0 -c "REINDEX DATABASE template0;" 2>/dev/null || true
sudo -u postgres psql -d template1 -c "REINDEX DATABASE template1;" 2>/dev/null || true
sudo -u postgres psql -d postgres -c "REINDEX DATABASE postgres;" 2>/dev/null || true

info "PostgreSQL collation fix complete"

# ---------- Run BloodHound Setup ----------
info "Running bloodhound-setup..."
bloodhound-setup <<EOF || warn "BloodHound setup encountered issues (may already be configured)"
y
EOF

info "BloodHound setup complete"

# ---------- RustHound-CE Installation ----------
info "Installing RustHound-CE..."
cd "$WORKDIR"

if [ ! -d "$RUSTHOUND_DIR" ]; then
  info "Cloning RustHound-CE repository..."
  git clone https://github.com/g0h4n/RustHound-CE.git "$RUSTHOUND_DIR"
else
  info "RustHound-CE already cloned, pulling latest changes..."
  cd "$RUSTHOUND_DIR"
  git pull || true
fi

cd "$RUSTHOUND_DIR"

# Install Rust toolchain if missing
if ! command -v cargo >/dev/null 2>&1; then
  info "Installing Rust toolchain..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
  source "$HOME/.cargo/env"
fi

info "Building RustHound-CE (this may take a few minutes)..."
make release

# Install binary
if [ -f target/release/rusthound-ce ]; then
  sudo cp -f target/release/rusthound-ce /usr/local/bin/rusthound-ce
  sudo chmod +x /usr/local/bin/rusthound-ce
  info "✓ rusthound-ce installed to /usr/local/bin/rusthound-ce"
else
  warn "RustHound-CE binary not found after build"
fi

# ---------- BloodHound.py Clone ----------
info "Setting up BloodHound.py..."
cd "$WORKDIR"

if [ ! -d "$BH_PY_DIR" ]; then
  info "Cloning BloodHound.py repository..."
  git clone https://github.com/dirkjanm/BloodHound.py.git "$BH_PY_DIR"
  cd "$BH_PY_DIR"
  
  # Install Python dependencies
  info "Installing Python dependencies..."
  python3 -m pip install --user -q . || warn "Failed to install BloodHound.py dependencies"
else
  info "BloodHound.py already cloned"
  cd "$BH_PY_DIR"
  git pull || true
fi

# ---------- Summary ----------
echo
info "=========================================="
info "Setup Complete!"
info "=========================================="
echo
echo "Tools installed:"
echo "  • BloodHound: Run with 'bloodhound' command"
echo "  • RustHound-CE: /usr/local/bin/rusthound-ce"
echo "  • BloodHound.py: $BH_PY_DIR"
echo
echo "Working directory: $WORKDIR"
echo
echo "Quick start:"
echo "  1) Start BloodHound: bloodhound"
echo "  2) Collect data with RustHound-CE:"
echo "     rusthound-ce -d domain.local -u username -p password -o output.zip"
echo "  3) Or use BloodHound.py:"
echo "     cd $BH_PY_DIR"
echo "     python3 bloodhound.py -c All -d domain.local -u username -p password"
echo
