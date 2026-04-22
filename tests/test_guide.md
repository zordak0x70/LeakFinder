# TEST 1

## Prerequisites

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential cmake git libgit2-dev libhs-dev

# On macOS with Homebrew
brew install libgit2 hyperscan

# Verify installation
pkg-config --cflags --libs libgit2 hyperscan
```

---

## 🔨 Build

```bash
# Clone (or navigate to) the project
git clone https://github.com/zordak0x70/LeakFinder.git

# Compile
mkdir build
meson setup --wipe build .
cd build && ninja

# Run
./leakfinder -c ../tests/leaker.toml /path/to/go/
```

**Expected output:**
```
[INFO] Blob Scanner starting (Target Batch: 350MB, Workers: 8)
[PROD] Iterating Object Database for files...
[PROD] Production complete. XX batches queued.
[W0] Worker finished.
...

========== RESULTS ==========
Total Blobs Scanned     : 242829
Total Data Scanned      : 7.33 GB
Total Secrets Found     : 5000 (Maximum)
Elapsed time            : 115.0 seconds
Throughput              : 65.26 MB/sec
==============================
(These are the result on my machine, so execpt something like this)
```

**🎉 Happy testing!**
