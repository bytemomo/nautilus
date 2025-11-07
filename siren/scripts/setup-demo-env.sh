#!/usr/bin/env bash
set -euo pipefail

NS_NAME=${NS_NAME:-siren-client}
VETH_HOST=${VETH_HOST:-siren0}
VETH_NS=${VETH_NS:-siren0-peer}
HOST_IP=${HOST_IP:-10.13.37.1/24}
NS_IP=${NS_IP:-10.13.37.2/24}
HOST_GW=${HOST_GW:-10.13.37.1}

usage() {
	cat <<EOF
Usage: $0 <up|down>

Creates a lightweight test topology:
  [client namespace (${NS_NAME})] <--veth--> [host (${VETH_HOST})]

Run with sudo so the script can manage namespaces and links.
EOF
	exit 1
}

if [[ $# -ne 1 ]]; then
	usage
fi

cmd=$1

exists_ns() {
	ip netns list | grep -qw "${NS_NAME}"
}

exists_link() {
	ip link show "${VETH_HOST}" >/dev/null 2>&1
}

case "$cmd" in
up)
	if exists_ns || exists_link; then
		echo "Namespace or link already exists. Run '$0 down' first if you want a clean slate."
		exit 0
	fi

	ip netns add "${NS_NAME}"
	ip link add "${VETH_NS}" type veth peer name "${VETH_HOST}"
	ip link set "${VETH_NS}" netns "${NS_NAME}"

	ip addr add "${HOST_IP}" dev "${VETH_HOST}"
	ip link set "${VETH_HOST}" up

	ip netns exec "${NS_NAME}" ip addr add "${NS_IP}" dev "${VETH_NS}"
	ip netns exec "${NS_NAME}" ip link set lo up
	ip netns exec "${NS_NAME}" ip link set "${VETH_NS}" up
	ip netns exec "${NS_NAME}" ip route add default via "${HOST_GW}"

	echo "Topology ready:"
	echo "  Host interface : ${VETH_HOST} @ ${HOST_IP}"
	echo "  Client ns      : ${NS_NAME} (${NS_IP})"
	;;
down)
	if exists_ns; then
		ip netns delete "${NS_NAME}"
	fi
	if exists_link; then
		ip link delete "${VETH_HOST}"
	fi
	echo "Topology removed."
	;;
*)
	usage
	;;
esac
