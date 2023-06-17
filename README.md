# JSON Web Token Issuer

This is a Restful service that issues a JWT. The request payload must include a client token which is another JWT itself.

## Build the binary

```bash
cargo build --release
```

## Run

A RSA 256 private key is required. Use the `PEM_FILE` environment to specify it path.
```bash
PEM_FILE=<private_key_path> ./target/release/jwt_issuer
```

## Logging level

There is no log by default. To set a logging level, use the `RUST_LOG` environment variable. For example, to  turn on the debug log, 

```bash
RUST_LOG=debug PEM_FILE=<private_key_path> ./target/release/jwt_issuer
```

## Development

The following VS Code plugins are required.

- rust-analyzer
- better toml
- crates
- error lens
- codelldb

To debug the code, build the code first and update the `launch.json` with the right path to the binary under `program`.

```bash
cargo build -v
```

Here is a sample `launch.json`:

```json
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "type": "lldb",
            "request": "launch",
            "name": "rust is fun",
            "program": "${workspaceRoot}/target/debug/jwt_issuer",
            "args": [],
            "cwd": "${workspaceRoot}",
            "sourceLanguages": ["rust"]
        }
    ]
}
```