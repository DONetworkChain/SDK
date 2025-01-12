#!/bin/bash

SHDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROTODIR=${SHDIR}/../src/proto/src
PROTOC=${SHDIR}/protoc/protoc
OUTDIR=${SHDIR}/../src/proto/

for proto in `ls $PROTODIR`
do
    echo "processing--->"${proto}
    $PROTOC -I=$PROTODIR --cpp_out=$OUTDIR ${proto} 
done




# -------------
# for proto in `find $PROTODIR -name *.proto`

