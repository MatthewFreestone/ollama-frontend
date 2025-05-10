# OLLAMA FRONTEND DEVELOPMENT GUIDE

## Build Commands
- Build backend: `cd backend && cargo build`
- Build frontend: `cd frontend && cargo build`
- Build frontend wasm: `cd frontend && wasm-pack build --target web`
- Run backend: `cd backend && cargo run`
- Run frontend dev server: `cd frontend && trunk serve`

## Test Commands
- Test backend: `cd backend && cargo test`
- Test frontend: `cd frontend && cargo test`
- Test single function: `cargo test function_name`

## Lint Commands
- Lint code: `cargo clippy`
- Format code: `cargo fmt`

## Code Style Guidelines
- Use 4-space indentation
- Prefer Result<T, E> for error handling with descriptive error types
- Follow Rust naming conventions: snake_case for variables/functions, CamelCase for types
- Group imports by external crates then internal modules
- Avoid unwrap() in production code, use proper error handling
- Document public APIs with rustdoc comments
- Prefer async/await for asynchronous code
- Keep functions small and focused on a single responsibility