#!/usr/bin/env bash
set -e
REPO="Fonners/AI-Subdomain-Enumerator"
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
echo "[*] Installing Atlas ${LATEST}..."
curl -fsSL "https://github.com/${REPO}/releases/download/${LATEST}/atlas.py" -o /tmp/atlas.py
sudo install -m 0755 /tmp/atlas.py /usr/local/bin/atlas
rm /tmp/atlas.py
pip install html2text nltk subwiz anthropic --break-system-packages --quiet
echo "[+] Done! Run: atlas -d example.com"
