#!/bin/sh


if [ $# != 1 ]; then
	echo "./compile.sh progamme"
	exit
fi

echo "compile started"
payload=$1

gcc -o out binaryWaf.c -lpthread -g -static
#strip out 
python binaryWaf.py -s out -p $payload -o "new_$payload"
chmod +x "new_$payload"
rm out

echo "new wrapped filename is new_$payload"
