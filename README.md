# **LeakFinder**
Git secret scanner 9.2x faster than gitleaks. Forensic-grade scan of the entire object database (including unreachable objects).

## Version & Development

🚧 STILL IN VERY EARLY DEVELOPMENT!! 🚧
I didn't even release the fully working beta...

**v0.0.1** — Stable but very incomplete release. Full ODB scan with zero false orphans, 9.25x faster than gitleaks, complete ref coverage (heads, tags, stash, remotes). Still no user-definable regexes at runtime, a jit implementaion will be essential

**TODO:** Consult TODO.md for a clear roadmap of the current objectives. (Like a in-depth analysis of the tool)

## Benchmarks

LeakFinder is written in pure C and optimized for performance. On the official Go repository, it achieves a scan speed of **73.44 MB/s**, making it approximately **9.3x faster** than gitleaks (7.84 MB/s).

### Performance Comparison

| Tool | Language | Throughput | Relative Speed |
| :--- | :---: | :---: | :---: |
| **LeakFinder** | **C** | **73.44 MB/s** | **9.3x~ Faster** |
| gitleaks | Go | 7.84 MB/s | Baseline |

**LeakFinder in action:**

![LeakFinder Benchmark]()

**gitleaks in action:**

![gitleaks Benchmark]()
```

# How to build the project

Select build type (release or debug):

**Build:**
```bash
meson setup build --buildtype=release
ninja -C build
```

**Debug:**
```bash
meson setup build-debug --buildtype=debug  
ninja -C build-debug
```

**Run:** `./build/leakfinder /path/to/repo`
