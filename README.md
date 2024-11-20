## 1 - Installation of OpenSSL 
* **STEP 1**: 
Download the library from the official website:
```bash
wget https://www.openssl.org/source/openssl-3.3.2.tar.gz
tar -xvf openssl-3.3.2.tar.gz
cd openssl-3.3.2
```
* **STEP 2**: 
Let's start the configuration:
```bash
./Configure --prefix=/opt/openssl-3.3.2 no-shared
```
* **STEP 3**:
 Installation:
```bash
make -j$(nproc)
sudo make install
```
* **STEP 4**: 
Check the installation by looking at specified version:
```bash
/opt/openssl-3.3.2/bin/openssl version
```
* **STEP 5**:
Add and activate the oqs-provider to OpenSSL 3.3.2 list:
```bash
sudo nano /opt/openssl-3.3.2/ssl/openssl.cnf
```
Modify the opened file by adding:
```bash
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
```
* **STEP 6**:
For convenience, we can add a direct alias to version 3.3.2:
```bash
sudo nano .bashrc
# sudo nano .bash_aliases
```
So, add:
```bash
alias openssl3='/opt/openssl-3.3.2/bin/openssl'
```

## 2 - Installation of liboqs
* **STEP 1**: 
Install all of needed dependencies:
```bash
sudo apt install astyle cmake gcc \
    ninja-build libssl-dev python3-pytest \
    python3-pytest-xdist unzip xsltproc \
    doxygen graphviz python3-yaml valgrind
```
* **STEP 2**:
Download liboqs:
```bash
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
```
* **STEP 3**:
Build liboqs:
```bash
mkdir build && cd build
cmake -GNinja ..
ninja
```
* **STEP 4**: 
Verify the installation:
```bash
ninja run_tests
ninja gen_docs
```

## 3 - Installation of oqs-provider

* **STEP 1**:
In root directory, ~/, clone the folder of oqs-provider:

```bash
git clone --branch main --recursive \
    https://github.com/open-quantum-safe/oqs-provider.git

cd ./oqs-provider
```

* **STEP 2**: Execute the build with the following steps. Then define the build type, specifying the flag -DOQS_KEM_ENCODERS=ON to enable KEM encoding (e.g. Kyber):
```bash
cmake -S . -B build \
    -DOPENSSL_ROOT_DIR=/opt/openssl-3.3.2 \
    -DOPENSSL_LIBRARIES=/opt/openssl-3.3.2/lib64 \
    -Dliboqs_DIR=/opt/liboqs/lib/cmake/liboqs \
    -DOQS_KEM_ENCODERS=ON
```
Build it:
``` bash
cmake --build build
sudo cmake --install build
```
* **STEP 3**: 
(if needed) Defining the environment variable for OpenSSL modules (no persistance):
```bash
export OPENSSL_MODULES=/opt/openssl-3.3.2/lib64/ossl-modules
```
* **STEP 4**:
Validate the installation:

```bash
cd ./build
ctest --parallel 5 --rerun-failed --output-on-failure -V
```
Check if files are right located:

```bash
ls /opt/openssl-3.3.2/lib64/ossl-modules
```
* **STEP 5**: Check oqsprovider in the providers' list:
```bash
openssl3 list -providers
```
If it does not appear in the list , check if STEP 5 of [1 - Installation of OpenSSL](#1---installation-of-openssl) was correctly executed.

View KEM supported algorithm list:
 ```bash
openssl3 list -kem-algorithms
```
View digital signature supported algorithm list:
```bash
openssl3 list -signature-algorithms
```
