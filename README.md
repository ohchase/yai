## Yai

Yet Another Injector for windows x64 dlls

```
Yet Another Injector for windows x64 dlls.

Usage: yai.exe --target <TARGET> --payload <PAYLOAD>

Options:
  -t, --target <TARGET>    Process name to inject into
  -p, --payload <PAYLOAD>  Absolute path to payload dll
  -h, --help               Print help information
  -V, --version            Print version information
```

### Library

You can use `yai` as a library as well. Add `yai` to your `Cargo.toml` and call `yai::inject_into`:

```rust
yai::inject_into("payload.dll", 1234 /* process id */);
```
