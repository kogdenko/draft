#!/bin/bash

set -o nounset
set -o errexit

case "${PLUTO_VERB}" in
    up-client)
	echo "up-client"
	echo "PLUTO_ME=${PLUTO_ME}"
	echo "PLUTO_PEER=${PLUTO_PEER}"
	echo "PLUTO_PEER_ID=${PLUTO_PEER_ID}"
	echo "PLUTO_PEER_CLIENT=${PLUTO_PEER_CLIENT}"
	echo "PLUTO_REQID=${PLUTO_REQID}"
	echo "PLUTO_UNIQUEID=${PLUTO_UNIQUEID}"
        ;;
    down-client)
	echo "down-client"
	echo "PLUTO_REQID=${PLUTO_REQID}"
	echo "PLUTO_UNIQUEID=${PLUTO_UNIQUEID}"
        ;;
esac
