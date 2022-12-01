#!/bin/sh

disable()
{
	DEVICE=$1
	if grep $DEVICE /proc/acpi/wakeup | awk '{print $3}' |  grep enabled; then
		echo $DEVICE > /proc/acpi/wakeup
	fi
}

disable PTXH
disable GPP0
