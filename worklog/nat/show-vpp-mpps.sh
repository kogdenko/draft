#!/bin/bash
RX_CUR=
TX_CUR=

read_rxtx()
{
	f=`mktemp`

	vppctl 'show inte' | grep -A 3 ens1f0 > $f

	RX_CUR=`grep 'rx packets' $f  | awk '{print $7}'`
	TX_CUR=`grep 'tx packets' $f  | awk '{print $3}'`
}


read_rxtx

RX_PRV=$RX_CUR
TX_PRV=$TX_CUR

echo "ipps		opps"

while :
do
	sleep 1
	read_rxtx

	ipps=`calc "($RX_CUR - $RX_PRV)/1000000" | xargs `
	opps=`calc "($TX_CUR - $TX_PRV)/1000000" | xargs`

	echo "${ipps}mpps	${opps}mpps"

	RX_PRV=$RX_CUR
	TX_PRV=$TX_CUR

done
