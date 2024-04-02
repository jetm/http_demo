# http demo

## Build

```sh
cmake -S . -B build -G Ninja && cmake --build build --clean-first && ./build/http_demo http://<SERVER_ADDRESS>[:SERVER_PORT]/FILE
```
