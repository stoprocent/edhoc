g++ aes.c aes-ccm.c aes-enc.c vectors.cpp -lsodium -o vectors.exec -Ilibsodium/src/libsodium/include -Llibsodium/src -std=c++17
