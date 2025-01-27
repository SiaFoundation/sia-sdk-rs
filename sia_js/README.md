# Sia SDK for JavaScript

This is a JavaScript SDK for interacting with the Sia network. It is built using Rust and WebAssembly and aims to provide a native-feeling interface for JavaScript developers.

## nodejs Example

### Build
```bash
wasm-pack build --target nodejs
```

### Run
```bash
cd example/nodejs
npm i
node index.js
```

## Browser Example

### Build
```bash
wasm-pack build
```

### Run
```bash
cd example/web
npm i
npm run start
```
