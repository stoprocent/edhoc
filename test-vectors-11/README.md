# Test Vectors Generator

### 1. You need to init mbedtls submodule first

```
$ git submodule update --init --recursive
$ cd test-vectors-11
```

### 2. Build MbedTLS Library

```
$ cd mbedtls
$ make no_test
$ cd ..
```

### 3. Adjust Vectors

You can edit `vectors.cpp` and add more calls to:

```
void test_vectors( EDHOCKeyType type_I, COSECred credtype_I, COSEHeader attr_I,
                   EDHOCKeyType type_R, COSECred credtype_R, COSEHeader attr_R,
                   int selected_suite, int seed, bool complex = false, bool comma = true )
```

in `int main( void )`

### 4. Build Test Vectors

Linux or Mac

```
$ chmod +x build.sh
$ ./build.sh
```

Windows

```
build.bat
```

### 5. Run Test Vectors

Linux or Mac

```
$ ./vectors
```

Windows

```
vectors.exe
```