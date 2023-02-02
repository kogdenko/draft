#!/bin/sh

disable()
{
	DEVICE=$1
	if grep $DEVICE /proc/acpi/wakeup | awk '{print $3}' |  grep enabled; then
		echo $DEVICE > /proc/acpi/wakeup
	fi
}

for file in `grep -l . /sys/bus/usb/devices/*/power/wakeup`; do
	echo disabled > $file
done

disable PTXH
disable GPP0
