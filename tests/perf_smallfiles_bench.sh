#!/bin/bash
# Small-files perf microbench. Args: <dir> <N>
set -eu
DIR="${1:-/tmp/bench}"
N="${2:-1000}"

mkdir -p "$DIR"
rm -rf "$DIR"/*

echo "== bench dir: $DIR, N=$N =="

# 1. Create N empty files
T0=$(date +%s.%N)
for i in $(seq 1 $N); do : > "$DIR/f$i"; done
T1=$(date +%s.%N)
echo "create_empty: $(awk "BEGIN{print $T1-$T0}")s ($(awk "BEGIN{printf \"%.0f\", $N/($T1-$T0)}") ops/s)"

# 2. Stat N files
T0=$(date +%s.%N)
for i in $(seq 1 $N); do stat "$DIR/f$i" >/dev/null; done
T1=$(date +%s.%N)
echo "stat:         $(awk "BEGIN{print $T1-$T0}")s ($(awk "BEGIN{printf \"%.0f\", $N/($T1-$T0)}") ops/s)"

# 3. Write 4KB to N files
DATA=$(head -c 4096 /dev/urandom | base64 | head -c 4096)
T0=$(date +%s.%N)
for i in $(seq 1 $N); do echo -n "$DATA" > "$DIR/f$i"; done
T1=$(date +%s.%N)
echo "write_4k:     $(awk "BEGIN{print $T1-$T0}")s ($(awk "BEGIN{printf \"%.0f\", $N/($T1-$T0)}") ops/s)"

# 4. Read N files
T0=$(date +%s.%N)
for i in $(seq 1 $N); do cat "$DIR/f$i" >/dev/null; done
T1=$(date +%s.%N)
echo "read_4k:      $(awk "BEGIN{print $T1-$T0}")s ($(awk "BEGIN{printf \"%.0f\", $N/($T1-$T0)}") ops/s)"

# 5. Delete N files
T0=$(date +%s.%N)
for i in $(seq 1 $N); do rm "$DIR/f$i"; done
T1=$(date +%s.%N)
echo "delete:       $(awk "BEGIN{print $T1-$T0}")s ($(awk "BEGIN{printf \"%.0f\", $N/($T1-$T0)}") ops/s)"

# 6. Bulk create + list
T0=$(date +%s.%N)
for i in $(seq 1 $N); do : > "$DIR/g$i"; done
T1=$(date +%s.%N)
ls "$DIR" | wc -l > /dev/null
T2=$(date +%s.%N)
echo "create_bulk:  $(awk "BEGIN{print $T1-$T0}")s ($(awk "BEGIN{printf \"%.0f\", $N/($T1-$T0)}") ops/s)"
echo "readdir:      $(awk "BEGIN{print $T2-$T1}")s"
rm -rf "$DIR"/*

# 7. Concurrent write throughput: K worker shells, each writing N/K files
K="${3:-8}"
PER=$((N / K))
DATA=$(head -c 4096 /dev/urandom | base64 | head -c 4096)
T0=$(date +%s.%N)
for w in $(seq 1 $K); do
  (
    for j in $(seq 1 $PER); do
      echo -n "$DATA" > "$DIR/cw_${w}_${j}"
    done
  ) &
done
wait
T1=$(date +%s.%N)
TOTAL=$((PER * K))
echo "concurrent_write_4k(K=$K): $(awk "BEGIN{print $T1-$T0}")s ($(awk "BEGIN{printf \"%.0f\", $TOTAL/($T1-$T0)}") ops/s, $TOTAL files)"
rm -rf "$DIR"/*

echo "== done =="
