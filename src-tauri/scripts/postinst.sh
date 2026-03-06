#!/bin/bash
# Post-install script for sv-subscriber .deb package
# Sets CAP_NET_RAW so the app can capture raw Ethernet packets without running as root
setcap cap_net_raw,cap_net_admin=eip /usr/bin/sv-subscriber
