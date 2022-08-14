#!/bin/sh
if grep GPP0 /proc/acpi/wakeup | awk '{print $3}'| grep enabled; then
	echo GPP0 > /proc/acpi/wakeup
fi
