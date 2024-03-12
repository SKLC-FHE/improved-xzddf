Implementation of Improved-xzddf
=====================================
We have further improved the xzddf method using the generator and  revision the framework of bootstrapping. Bootstrapping time within 10ms.
### Requirements
A C++ compiler, the NTL libraries.
## Run the code
```
mkdir build
cd build
cmake -DWITH_NTL=ON  -DNATIVE_SIZE=32 -DWITH_NATIVEOPT=ON -DCMAKE_C_COMPILER=clang-12 -DCMAKE_CXX_COMPILER=clang++-12 -DWITH_OPENMP=OFF -DCMAKE_C_FLAGS="-pthread" -DCMAKE_CXX_FLAGS="-pthread" ..
make 
```
