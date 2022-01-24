# v2ray-agent menu

* * *

# content

- [1. Script installation] (#1vlesstcptlsvlesswstlsvmesstcptlsvmesswstlstrojan-camouflage site-five-in-one coexistence script)
    - [Features](#feature)
    - [Notes] (#Notes)
    - [install script](#install script)

* * *

# Eight-in-one multi-script + NGINX camouflage site

## Features

- Install [Xray-core[XTLS]](https://github.com/XTLS/Xray-core), v2ray-core
- Support switching pre-[VLESS XTLS -> Trojan XTLS], [Trojan XTLS -> VLESS XTLS]
- Support mutual reading of configuration files between different cores
- Support VLESS/VMess/trojan protocol
- Support Debian, Ubuntu, Centos, and mainstream CPU architectures. **It is not recommended to use Centos and lower version systems, Centos6 is no longer supported after 2.3.x**

- Support personalized installation
- Support multi-user management
- Support Netflix detection, support DNS streaming media unlock, support any door unlock Netflix
- Install and reinstall any combination without uninstalling
- Support to retain Nginx and tls certificates when uninstalling. If the certificate applied by acme.sh is valid, it will not be reissued
- Support IPv4[in]->IPv6 offload[out]
- Support WARP offload
- Support log management
- Supports multi-port configuration

## Supported installation types

- VLESS+TCP+TLS
- VLESS+TCP+xtls-rprx-direct [**Recommended**]
- VLESS+gRPC+TLS [support CDN, IPv6, low latency]
- VLESS+WS+TLS [support CDN, IPv6]
- Trojan+TCP+TLS [**Recommended**]
- Trojan+TCP+xtls-rprx-direct [**Recommended**]
- Trojan+gRPC+TLS [support CDN, IPv6, low latency]
- VMess+WS+TLS [support CDN, IPv6]

## Combination recommendation

- Transit /gia/AS4837/AS9929 ---> VLESS+TCP+TLS/XTLS, Trojan [xtls-rprx-direct of XTLS is recommended]
- Mobile Broadband---> VMESS+WS+TLS/VLESS+WS+TLS/VLESS+gRPC+TLS/Trojan+gRPC+TLS + Cloudflare
- cloudflare-> VLESS+gRPC+TLS/Trojan+gRPC+TLS [multiplexing, low latency]

## install script

- Support shortcut startup. After installation, enter [**vasma**] in the shell to open the script. The script execution path [**/etc/v2ray-agent/install.sh**]

- Latest Version [recommended]

> wget -P /root -N --no-check-certificate "[../master/install.sh?raw=1](../master/install.sh?raw=1)" && chmod 700 /root/install.sh && /root/install.sh