#!/bin/bash

###############################################################################
# RTSSP Performance Testing Script
# Captures REAL performance metrics: duration, frames, FPS, throughput
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$SCRIPT_DIR/test_results/performance_results.txt"
mkdir -p "$SCRIPT_DIR/test_results"

cleanup() { pkill -f "java hjStreamServer" 2>/dev/null; pkill -f "java hjUDPproxy" 2>/dev/null; sleep 1; }
trap cleanup EXIT

# Compile
cd "$SCRIPT_DIR/hjStreamServer" && javac -q *.java 2>/dev/null
cd "$SCRIPT_DIR/hjUDPproxy" && javac -q *.java 2>/dev/null

> "$RESULTS"
echo "Performance Test Results - $(date)" >> "$RESULTS"
echo "" >> "$RESULTS"

run_test() {
    local name=$1 cipher=$2 keysize=$3 movie=$4
    echo "▶ $name"
    cleanup
    sed -i "s|^cipher.algorithm=.*|cipher.algorithm=$cipher|" "$SCRIPT_DIR/hjStreamServer/Cryptoconfig.conf"
    sed -i "s|^cipher.keysize=.*|cipher.keysize=$keysize|" "$SCRIPT_DIR/hjStreamServer/Cryptoconfig.conf"
    
    (cd "$SCRIPT_DIR/hjUDPproxy" && timeout 200 java hjUDPproxy > /tmp/px.log 2>&1) &
    px=$!
    sleep 2
    
    start=$(date +%s)
    cd "$SCRIPT_DIR/hjStreamServer" && timeout 195 java hjStreamServer "$SCRIPT_DIR/hjStreamServer/movies/$movie" localhost 5000 > /tmp/sr.log 2>&1
    end=$(date +%s)
    dur=$((end - start))
    
    kill $px 2>/dev/null
    sleep 1
    
    frames=$(grep "all frames sent:" /tmp/sr.log | grep -oE '[0-9]+' | tail -1)
    fps=$(grep "Throughput.*fps" /tmp/sr.log | grep -oE '[0-9]+' | head -1)
    kbps=$(grep "Throughput.*Kbps" /tmp/sr.log | grep -oE '[0-9]+' | head -1)
    
    echo "  Duration: ${dur}s | Frames: $frames | FPS: $fps | Kbps: $kbps"
    { echo "$name: ${dur}s, $frames frames, $fps fps, $kbps Kbps"; } >> "$RESULTS"
}

echo "=== RTSSP Performance Tests ==="
echo ""
run_test "Test 1: RTSSP+AES/CTR/256" "AES/CTR/NoPadding" "256" "cars.dat"
run_test "Test 2: RTSSP+AES/GCM/256" "AES/GCM/NoPadding" "256" "monsters.dat"
run_test "Test 3: RTSSP+AES/GCM/128" "AES/GCM/NoPadding" "128" "cars.dat"

echo ""
echo "=== Final Results ==="
cat "$RESULTS"
