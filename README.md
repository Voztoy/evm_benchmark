
- Cài ubuntu
   ```bash
   wsl --install
   ```

- Cài C++
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install build-essential -y
   g++ --version
   sudo apt install libssl-dev -y
   ```
- Build và chạy
   ```bash
   g++ evm_benchmark.cpp sha3.c -o evm_benchmark \
    -O3 -march=native -funroll-loops -flto -fopenmp \
    -lssl -lcrypto
  ./evm_benchmark
   ```
   Hoặc
   ```bash
   sudo apt update
   sudo apt install build-essential libssl-dev
   g++ evm_benchmark.cpp sha3.c -o evm_benchmark -lssl -lcrypto
   ./evm_benchmark
   ```
  
