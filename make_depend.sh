#!/bin/sh


echo "-- start make depend:"

SHDIR=$(dirname `readlink -f $0`)
BUILD_WASM_LIB=$2
echo "make_depend.sh execute dir:" $SHDIR

PROTOBUF_DIR=./protobuf
OPENSSL_DIR=./openssl
CRYPTOPP_DIR=./cryptopp
COMPILE_NUM=`cat /proc/cpuinfo| grep  "processor" | wc -l`;

# openssl
cd $SHDIR
if [ -d ${OPENSSL_DIR} ];
then
    echo "openssl compile";
else
    tar -xvf ./3rd/openssl-3.0.5.tar.gz;
    mv openssl-3.0.5 openssl;
    cd ${OPENSSL_DIR};
    if [ "$BUILD_WASM_LIB" = "ON" ];
    then
        emconfigure ./Configure linux-generic64 --prefix=$EMSCRIPTEN/system &&
        sed -i 's|^CROSS_COMPILE.*$|CROSS_COMPILE=|g' Makefile &&
        emmake make -j 10 build_generated libssl.a libcrypto.a &&
        cp libcrypto.a ../lib/linux/ &&
        cp libssl.a ../lib/linux/;
    else
        ./Configure && make -j$COMPILE_NUM && make install && cp libcrypto.a ../lib/linux/ && cp libssl.a ../lib/linux/;
    fi;
fi;

# protobuf
cd $SHDIR
if [ -d ${PROTOBUF_DIR} ]; 
then 
    echo "protobuf compile";
else
    unzip ./3rd/protobuf-cpp-3.21.9.zip -d ./;
    mv protobuf-3.21.9 protobuf;
    cd ${PROTOBUF_DIR};
    if [ "$BUILD_WASM_LIB" = "ON" ];
    then
          ./autogen.sh &&
          emconfigure ./configure --host=none-none-none &&
          emmake make -j10 &&
          cp ./src/.libs/libprotobuf.a ../lib/linux/;
    else
         mkdir build && cd build &&  cmake .. -Dprotobuf_BUILD_TESTS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON && make -j$COMPILE_NUM && cp libprotobuf.a ../../lib/linux/;
    fi;
fi;

# cryptopp
cd $SHDIR
if [ -d ${CRYPTOPP_DIR} ]; 
then 
    echo "cryptopp compile";
else
    unzip ./3rd/cryptopp-CRYPTOPP_8_9_0.zip -d ./;
    mv cryptopp-CRYPTOPP_8_9_0 cryptopp;
    cd ${CRYPTOPP_DIR}
    if [ "$BUILD_WASM_LIB" = "ON" ];
    then
        emmake make -j$COMPILE_NUM && cp ./libcryptopp.a ../lib/linux/;
    else
        make && make test && sudo make install && cp ./libcryptopp.a ../lib/linux/;
    fi;
fi;

cd $1
echo "-- make depend done"

 


