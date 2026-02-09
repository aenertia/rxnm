# Building RXNM for Minimal Targets

For constrained environments (SpiLinux, Embedded, Initramfs) **and** general distribution, we prioritize binary size and portability.

## The "Tiny" Profile (Recommended for Release)

We use **static linking** to create a zero-dependency binary. This is the recommended build for **ALL** targets (Embedded, Desktop, Server) because it eliminates `glibc` version mismatches and dynamic linker overhead.

### Build Strategy

The `make tiny` command automatically detects your environment:

1.  **Optimal:** If `musl-gcc` is found, it creates a ~50KB binary.
2.  **Fallback:** If not found (e.g., standard Buildroot/LibreELEC toolchains), it uses your standard `$(CC)` with `-static` to create a ~700KB binary.

Both strategies achieve **< 5ms startup latency** by bypassing the dynamic linker and OverlayFS lookups.

### Building inside Buildroot / LibreELEC

When building as a package within a larger build system, simply call:

```bash
make tiny CC="${TARGET_CC}"
```

The Makefile will detect that `musl-gcc` is missing from the cross-compilation environment and automatically produce the **Static Glibc** version. This is the intended behavior for these platforms.

### Option B: Building via Containers (For smallest size)

If you absolutely require the 50KB footprint but lack the toolchain, you can build via containers *if your host supports it*.


**Using Podman:**
```bash
podman run --rm -v $(pwd):/app -w /app alpine:latest sh -c "apk add --no-cache gcc musl-dev make bash && make tiny"
```

## Comparison

| Feature | Dynamic (Standard) | Static (Glibc) | Static (Musl) |
| :--- | :--- | :--- | :--- |
| **Startup** | ~15ms (Load overhead) | **~1ms (Instant)** | **~1ms (Instant)** |
| **Dependencies** | Requires host `glibc` | **None** | **None** |
| **Portability** | Low | **High** | **High** |
| **Size** | ~20KB (+ 2MB shared libs) | ~700KB | ~50KB |

**Conclusion:** Use `make tiny` for all distribution builds.
