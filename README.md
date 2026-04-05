# **LeakFinder**
Git secret scanner 9.2x faster than gitleaks. Forensic-grade scan of the entire object database (including unreachable objects).

## Version & Development

🚧 STILL IN VERY EARLY DEVELOPMENT!! 🚧
I didn't even release the fully working beta...

**v0.0.1** — Stable but very incomplete release. Full ODB scan with zero false orphans, 9.25x faster than gitleaks, complete ref coverage (heads, tags, stash, remotes).

**Current:** Active development focusing on regex accuracy and batch processing optimization.

## Benchmarks (Why its much faster than everything)

// TODO (Tomorrow! 06/04 i will release them officially)

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
