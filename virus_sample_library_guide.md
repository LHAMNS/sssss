# QuickQ/LetsVPN 恶意软件 — 病毒样本库入库指南

**报告编号:** MAL-2026-0301-QUICKQ
**日期:** 2026-03-01
**威胁等级:** 严重 (Critical)
**目标读者:** 杀毒引擎工程师、病毒库维护人员

---

## 一、威胁概述

**威胁名称建议：**
- 主分类: `Trojan.Win64.QuickQDropper` (外层安装器)
- 子分类:
  - `Trojan.Win64.FalconSDK` (libwin.dll 网络劫持组件)
  - `Trojan.Win32.FalconAnalytics` (LetsGoogleAnalytics.dll 数据外泄组件)
  - `Trojan.Win64.P2CDNBot` (pcdnacc7.exe P2CDN 僵尸节点)
  - `Trojan.Win64.ShellcodeLoader` (hfel.bmp/t7.bmp shellcode 加载器)

**关联恶意软件家族：**
- Winos 4.0 / Gh0st RAT 变种
- Farfli Backdoor
- BlackMoon / KRBanker
- Silver Fox / Void Arachne APT

---

## 二、签名入库清单

### 2.1 文件哈希签名（按优先级排序）

#### 优先级 P0 — 立即入库（外层安装器+核心载荷）

```
# 外层 ZIP 包
SHA256: 4bbf59be5e221a678560e02d233e0f4e36b55f51b9e7ec09b33f1ccfc11264c5
MD5:    ad188227e2e8a2175b543a9f7e3c1c98
名称:   K7j9aS6dM3J.zip
检测名: Trojan.Win64.QuickQDropper.A

# Inno Setup 安装器
SHA256: 4cff59555c0ad255e5be4d15c49f26cc75a8b234c02678bf292199afb00359a8
MD5:    c8e29f2147b5738c2239c290b14ccd4d
名称:   K7j9aS6dM3J.exe
检测名: Trojan.Win64.QuickQDropper.A

# P2CDN 引擎（DLL 侧加载宿主）
SHA256: a7750cd631e7de17bc3a3759c8408f0f13bcb5f2871c21bbcf2141335d30fe5e
名称:   pcdnacc7.exe
检测名: Trojan.Win64.P2CDNBot.A

# Shellcode 载荷 #1
SHA256: 4d63268cff6c9ab5b5ead98da46d913bc30470efc5c316d7a379fcf9b76c46be
名称:   hfel.bmp
检测名: Trojan.Win64.ShellcodeLoader.A

# Shellcode 载荷 #2
SHA256: df3ed6908ae63746ff4a8623e019689f5d4026a9127fbafd4564aff9e8250447
名称:   t7.bmp
检测名: Trojan.Win64.ShellcodeLoader.B

# 加密 ZIP 容器
SHA256: 3628b4d6879b91c4b5f4ddeb7ff30e6c8d2e69e4523c83e7fc18af67df84b6b4
名称:   tex1.bmp
检测名: Trojan.Win64.EncryptedPayload.A
```

#### 优先级 P1 — 尽快入库（加密载荷文件）

```
SHA256: fd2bfa8984ec6103fbeedfb6548ed3895187064748a59f813421a8c205c061d2  mdE0aaiVjk
SHA256: f1dbfe66d90bc18039eaa7bbf788b474c486d4009eac768f4167cbc79eecad2a  MsyGhIaI0X
SHA256: b033bf1b1364090d52457faaf731b0994b8ceb57dfd1ae277111df2b69045a67  nCn96s2Dhv
SHA256: a7ed451ea49bf16403f9fb5061c8899c542bf9bb92cec706f55bdfce043a81bc  oTAALIKshO
SHA256: dbacdd983c3b038d5d2cebbb4833226bc964eafa57547bd88181fcbe75150e54  Zchzmz1lq2
SHA256: 2f1c961b8c8f129b38f7d5a1f129734a1ccc87ffc7d57ebe06039765fc89159e  zHfyu5gufC
SHA256: effff6fda301579158932f6f29f728068aca440722d03b926de6ba04577b9fd0  Bglh35Jm4kY6jeA.875
SHA256: ad528cd7f3977f62638f77be6a5bd073d52e25d55932c98b998ef4d6cc230167  9zrOt7sfAfQd.YeL4
SHA256: 363b566730a9e0ff4ca0aa56dbdc8e5c056ec1b38fc297c2bf1d8ba73d8dd595  y5imjxKN4.S9aE
SHA256: 9f71853fc4a3d179fdd46bdbdc2f2314a7c457935f6975d855b78332c721d728  kYw3Hm96wkij7b3.D51b
SHA256: a7ae991c066d1d6eac317e3f51c73ae2f530649bda27f71efdd6020fba2dfb97  8b21vb39HnoNU.ct1h
SHA256: 2110fe67a17d8093cb223aead5c34f3ee0afe7c3cc49dcb2cca1dcb34616268e  rY2Dna2zHsvzbPT.T3mO
SHA256: 0b9713fbbe161306855e3d5fab9c4b3181e32b8a34e19776ce347460fb28acac  D2R0TjUGa.87l
SHA256: ad8114b87116a1a8c58969ea4f899cdbec23396be7a0129a783977573369c5d7  XzhVmgVLGHOd81e.8ry
SHA256: 5e0dbb11cbba4d89bda2a5de82a8df348da537edc79fcb4ae6b6e887d274e5c8  Qt1oRwXQ9yL.7k0
SHA256: 5bf8d17ef32ce9500f4645b87cc9b02c2b1e069fbb749d83802dcb4fd2444a22  8q1839723.t70j
SHA256: 55a914e64f63fb49ba9a49697fb7572b47915f6a11fa9c04d5b262ce2febd1ba  V2Y11a7IV7X8W.7AY
SHA256: 83ee5b24e60fa6f62e5ef1231c3b6069b59e99a6cf3d90323db6d29d47cb15c6  dijEupz40OU.Wab7
SHA256: 8325b993ef3bf0183d9d16343a2a158ec3dbad04fb9534dc8e13e6c5bfc43739  pcxm3n6.Pu6
SHA256: eae83eed78e5d58773f46c5ee53dd948eb9506e51758a8c19ca0695ee179d96c  T89kgc0FK35E.838
SHA256: 6c6f141b0bf2b0cfde2346680781a34896739314e3612811ce56082dca09248e  dH12K85.6LE
SHA256: 6411780670cfd5d6fff5e7ed6adc528591932e0572d17ee5b8532a6bf5a49fb3  YrmO6glXy0Bf2v.6be
SHA256: b9cb06b7a14393ffb3703b30ca2134b3b933fb77717d7f8a583948cdef423bfb  RlzkKSS0Rm.6dj
SHA256: 869f3e4ae02b56367a1d27bc3449781d7ce822f0b30df6b21e7812113ae49502  CT5iwW.S34

检测名: Trojan.Win64.EncryptedPayload.B (统一检测名)
```

#### 优先级 P2 — 跟进入库（NSIS 掩护安装器）

```
# NSIS 安装器（存在争议——本身可能是合法 LetsVPN，但在此上下文中作为恶意掩护）
SHA256: 22944c87ac71fc5a95198fe0b4ed51f9d8ae1759d5b840ba18c9e9f26902754a
名称:   picdjegdbt.exe
检测名: PUP.Win32.LetsVPN.Bundled（作为 PUP 而非直接恶意）

# 合法 BMP（可能含隐写数据）
SHA256: f861cbedbb14456acaeb70097dacbc0a8c1f3d0cf7b960dc54cf9d4af7b93801
名称:   d.bmp
检测名: Trojan.Win64.Steganography.A
```

### 2.2 启发式/通用检测规则

#### 规则 1: Inno Setup 安装器特征匹配

```
条件: PE 文件 AND 包含 "Inno Setup Setup Data (5.3.9)" AND 包含 "quaib-r"
     AND Overlay 大小 > 文件总大小 * 0.95
检测名: Trojan.Win64.QuickQDropper.Gen
```

#### 规则 2: BMP 伪装 Shellcode 检测

```
条件: 文件扩展名为 .bmp AND 文件头不以 0x42 0x4D ("BM") 开头
     AND 文件大小 > 1MB AND 文件大小 < 5MB
     AND 包含 x86-64 指令特征 (0x48 0x83, 0x49 0x89, 0x4C 0xE5)
检测名: Trojan.Win64.ShellcodeBMP.Gen
```

#### 规则 3: 高熵加密载荷检测

```
条件: 文件大小 > 1MB AND 文件大小 < 20MB
     AND Shannon 熵值 > 7.99
     AND 文件头不匹配任何已知文件格式
     AND 父目录名为随机字符串(长度 8-12, 混合大小写字母数字)
检测名: Trojan.Win64.EncryptedPayload.Gen
```

#### 规则 4: Go 编译的恶意 DLL 检测

```
条件: PE DLL AND 文件大小 > 5MB
     AND 包含字符串 "bitbucket.org/letsgo-network/falcon"
     OR 包含字符串 "falcon.ipaddr-decrypt"
     OR 包含字符串 "falcon.log-encrypt"
检测名: Trojan.Win32.FalconSDK.Gen
```

#### 规则 5: GA4 数据外泄检测

```
条件: PE DLL AND 包含字符串 "LetsGoogleAnalyticsLib"
     AND 包含字符串 "google-analytics.com/mp/collect"
     AND 包含字符串 "\\.\pipe\LetsGoogleAnalytics"
检测名: Trojan.Win32.GA4Exfil.Gen
```

#### 规则 6: P2CDN 僵尸节点检测

```
条件: PE64 AND requireAdministrator
     AND 包含字符串 "PCDN_Client@peer@ku"
     OR 包含字符串 "&module=pcdn_acc"
     AND 包含导入 CreateRemoteThreadEx
检测名: Trojan.Win64.P2CDNBot.Gen
```

#### 规则 7: 被盗 Rockstar Games 证书检测

```
条件: PE 签名 Subject CN = "Rockstar Games, Inc."
     AND PE VersionInfo CompanyName = "163.com"
     OR PE PDB 路径包含 "netease"
     OR PE OriginalFilename = "acc.exe"
检测名: Trojan.Win64.StolenCert.RockstarGames
```

#### 规则 8: Inno Setup GUID 检测

```
条件: 注册表包含 {BB2534C2-0E4B-417f-B984-8573BA95DB03}
     OR 包含字符串 "quaib-r"
     AND Inno Setup 版本 = 5.3.9
检测名: Trojan.Win32.QuickQDropper.Inno
```

### 2.4 代码签名证书黑名单

| 证书签名者 | 颁发者 | 序列号 | 状态 |
|-----------|--------|--------|------|
| Rockstar Games, Inc. | DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 | `0d88c08f566d2b1f0c194db1f8cac9a9` | **被盗 — 应立即拉黑** |
| LetsGo Network Incorporated | GlobalSign GCC R45 CodeSigning CA 2020 | `39fc16a868afc14f526f1351` | **恶意使用 — 应列入灰名单** |
| KES Technologies | (自签名/Inno Setup) | N/A | **伪造身份** |

---

## 三、YARA 规则集

### 3.1 外层安装器检测

```yara
rule QuickQ_FakeVPN_Dropper {
    meta:
        description = "QuickQ/LetsVPN 伪装恶意安装器"
        author = "Security Research Team"
        date = "2026-03-01"
        reference = "MAL-2026-0301-QUICKQ"
        severity = "critical"
        malware_family = "QuickQDropper"

    strings:
        $inno = "Inno Setup Setup Data (5.3.9)" ascii
        $name = "quaib-r" ascii wide
        $dir1 = "uhjwxkky" ascii wide
        $dir2 = "kbyvnnp" ascii wide
        $exe1 = "pcdnacc7" ascii wide
        $exe2 = "picdjegdbt" ascii wide
        $mz = { 4D 5A }

    condition:
        $mz at 0 and (
            ($inno and $name) or
            (2 of ($dir1, $dir2, $exe1, $exe2))
        )
}
```

### 3.2 Falcon SDK 检测

```yara
rule Falcon_SDK_Malware {
    meta:
        description = "Falcon SDK 恶意网络劫持引擎"
        author = "Security Research Team"
        date = "2026-03-01"
        severity = "critical"
        malware_family = "FalconSDK"

    strings:
        $falcon1 = "falcon.api-agent-sdk.src" ascii
        $falcon2 = "falcon.client-sdk.src" ascii
        $falcon3 = "falcon.framework.src" ascii
        $falcon4 = "falcon.ipaddr-decrypt" ascii
        $falcon5 = "falcon.log-encrypt" ascii
        $letsgo = "bitbucket.org/letsgo-network" ascii
        $dns1 = "fakeDns" ascii
        $dns2 = "DNSDispatcher" ascii
        $dns3 = "restoreFakeDNSByRegistry" ascii
        $nic1 = "DisableNIC" ascii
        $nic2 = "RemoveNIC" ascii
        $intercept1 = "interceptIPv4" ascii
        $intercept2 = "ProcessTCP" ascii
        $sni = "UpdateSNI" ascii
        $pe = { 4D 5A }

    condition:
        $pe at 0 and (
            ($letsgo and 2 of ($falcon*)) or
            (3 of ($dns1, $dns2, $dns3, $nic1, $nic2, $intercept1, $intercept2, $sni))
        )
}
```

### 3.3 GA4 数据外泄检测

```yara
rule LetsGoogleAnalytics_Exfil {
    meta:
        description = "利用 Google Analytics 进行数据外泄的 DLL"
        author = "Security Research Team"
        date = "2026-03-01"
        severity = "high"
        malware_family = "GA4Exfil"

    strings:
        $ga4_lib = "LetsGoogleAnalyticsLib" ascii
        $ga4_collect = "google-analytics.com/mp/collect" ascii
        $ga4_debug = "google-analytics.com/debug/mp/collect" ascii
        $pipe = "\\.\x00p\x00i\x00p\x00e\x00\\\x00L\x00e\x00t\x00s\x00G\x00o\x00o\x00g\x00l\x00e" wide
        $pipe_ascii = "\\\\.\pipe\\LetsGoogleAnalytics" ascii
        $db = "LetsGoogleAnalytics.db" ascii
        $dev = "jason-xie-123" ascii
        $pe = { 4D 5A }

    condition:
        $pe at 0 and (
            ($ga4_lib and ($ga4_collect or $ga4_debug)) or
            ($pipe or $pipe_ascii) and $db or
            $dev
        )
}
```

### 3.4 P2CDN 僵尸节点检测

```yara
rule P2CDN_Bot_Agent {
    meta:
        description = "P2CDN 僵尸网络代理（快手/Kuaishou 关联）"
        author = "Security Research Team"
        date = "2026-03-01"
        severity = "critical"
        malware_family = "P2CDNBot"

    strings:
        $pcdn1 = "PCDN_Client@peer@ku" ascii
        $pcdn2 = "PCDN_Proxy@peer@ku" ascii
        $pcdn3 = "&module=pcdn_acc" ascii
        $pcdn4 = "--pcdn-domain" ascii
        $pcdn5 = "--enable-shell" ascii
        $api1 = "/peer/command/exit" ascii
        $api2 = "/peer/command/net" ascii
        $api3 = "/iku/log/info-upload.php" ascii
        $api4 = "/iku/log/feedback-upload.php" ascii
        $inject = "CreateRemoteThreadEx" ascii
        $pe = { 4D 5A }

    condition:
        $pe at 0 and (
            2 of ($pcdn*) or
            (1 of ($pcdn*) and 1 of ($api*)) or
            ($pcdn3 and $inject)
        )
}
```

### 3.5 BMP 伪装 Shellcode 检测

```yara
rule Shellcode_Disguised_BMP {
    meta:
        description = "伪装为 BMP 图像的 Shellcode 载荷"
        author = "Security Research Team"
        date = "2026-03-01"
        severity = "critical"

    strings:
        $not_bmp = { 42 4D }
        $x64_1 = { 49 89 [2] 81 C1 }
        $x64_2 = { 48 83 [2] 48 83 }
        $x64_3 = { C7 44 [2] 05 00 }
        $x64_4 = { 48 E5 [1] 5E C3 }

    condition:
        not $not_bmp at 0 and
        filesize > 1MB and
        filesize < 5MB and
        2 of ($x64_*)
}
```

### 3.6 PoW 分发页面检测

```yara
rule QuickQ_PoW_Download_Page {
    meta:
        description = "QuickQ PoW 保护的恶意下载页面"
        author = "Security Research Team"
        date = "2026-03-01"

    strings:
        $pow1 = "crypto.subtle.digest" ascii
        $pow2 = "api_get_task.php" ascii
        $pow3 = "api_verify.php" ascii
        $pow4 = "runPoW" ascii

    condition:
        3 of them
}
```

---

## 四、网络 IOC 入库

### 4.1 域名黑名单

```
# 主要分发域名（优先级 P0）
down.fx-quickq.com.cn
fx-quickq.com.cn

# 存储后端（优先级 P0）
qoxkjdi.oss-accelerate.aliyuncs.com

# C2 域名（优先级 P0）
d1dmgcawtbm6l9.cloudfront.net

# 关联恶意域名（优先级 P1）
ad59t82g.com
letevpn.world
```

### 4.2 IP 黑名单

```
# 已知 C2 IP（优先级 P0）
202.79.173.4
202.79.173.50
202.79.173.54
103.46.185.44
103.46.185.73
112.213.101.161
112.213.101.139
47.83.184.193
```

### 4.3 URL 路径特征

```
# P2CDN C2 路径
/peer/command/exit
/peer/command/net
/peer/config
/peer/debug
/peer/detect
/iku/log/feedback-upload.php
/iku/log/info-upload.php

# PoW 分发 API
/api_get_task.php
/api_verify.php
/download.php?type=kuailian
```

### 4.4 网络行为检测规则

```
# 规则 1: GA4 数据外泄检测
条件: HTTP POST 到 google-analytics.com/mp/collect
     且 measurement_id 参数值不在企业已知 GA4 属性列表中
     且 请求频率 > 10次/分钟
动作: 告警 + 阻断

# 规则 2: DNS 设置篡改检测
条件: 进程修改注册表键
     HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig
     且进程不是 svchost.exe 或 netsh.exe
动作: 告警 + 阻断

# 规则 3: 命名管道检测
条件: 创建命名管道匹配 \\.\pipe\LetsGoogleAnalytics-*
动作: 告警
```

---

## 五、注册表 IOC

### 5.1 持久化注册表键

```
# Winos 4.0 特征（P0）
HKCU\Console\IpDate
HKCU\Console\0
HKCU\SOFTWARE\MsUpTas

# DNS 劫持注册表路径（P0）
HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\(lets)

# 网卡参数修改（P1）
HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}
```

### 5.2 文件路径 IOC

```
# 恶意安装目录（本样本特有）
{安装目录}\uhjwxkky\*
{安装目录}\kbyvnnp\*

# Winos 4.0 文件
%LOCALAPPDATA%\insttect.exe
%APPDATA%\TrustAsia\*
%LOCALAPPDATA%\you.dll
%LOCALAPPDATA%\lastbld2Base.dll
%LOCALAPPDATA%\jli.dll
%LOCALAPPDATA%\dokan2.dll

# GA4 数据库
{安装目录}\LetsGoogleAnalytics.db

# 配置文件
{安装目录}\LetsPRO.ini

# Hosts 文件标记
# This template is calc by letsvpn, please do not edit this file
```

---

## 六、行为检测规则入库

### 6.1 进程行为规则

| 规则编号 | 条件 | 严重性 | 动作 |
|----------|------|--------|------|
| BHV-001 | 进程 A 调用 CreateRemoteThreadEx 注入到进程 B，且进程 A 的父进程是 Inno Setup 安装器 | 严重 | 阻断+告警 |
| BHV-002 | 进程读取 .bmp 文件后调用 VirtualAlloc(PAGE_EXECUTE_READWRITE) | 严重 | 阻断+告警 |
| BHV-003 | 非系统进程修改 DNSServerSearchOrder 注册表值 | 高危 | 告警 |
| BHV-004 | 非系统进程调用 DnsFlushResolverCache API | 中危 | 告警 |
| BHV-005 | 进程同时调用 DisableNIC 和 CreateRemoteThreadEx | 严重 | 阻断+告警 |
| BHV-006 | Go 编译的 DLL (大于 5MB) 通过 WMI 查询 Win32_NetworkAdapter | 高危 | 告警 |
| BHV-007 | 进程创建命名管道匹配 `\\.\pipe\LetsGoogleAnalytics-*` | 高危 | 告警 |
| BHV-008 | Inno Setup 安装器释放熵值 > 7.9 的文件到随机命名目录 | 高危 | 告警 |

### 6.2 网络行为规则

| 规则编号 | 条件 | 严重性 | 动作 |
|----------|------|--------|------|
| NET-001 | 对 google-analytics.com/mp/collect 发送异常高频 POST 请求 | 高危 | 告警 |
| NET-002 | TLS 握手 SNI 字段与目标 IP 对应的域名不匹配 | 高危 | 告警 |
| NET-003 | 连接到 CloudFront CDN 端点 d1dmgcawtbm6l9.cloudfront.net | 中危 | 告警 |
| NET-004 | UPnP 端口映射请求来自非用户主动操作 | 中危 | 告警 |
| NET-005 | WebSocket 连接到未知服务器且持续时间 > 30分钟 | 中危 | 监控 |

---

## 七、样本保存规范

### 7.1 样本命名

```
MAL-2026-0301-QUICKQ/
├── stage0_zip/
│   └── K7j9aS6dM3J.zip.quarantine
├── stage1_inno/
│   └── K7j9aS6dM3J.exe.quarantine
├── stage2_payload/
│   ├── pcdnacc7.exe.quarantine
│   ├── hfel.bmp.quarantine
│   ├── t7.bmp.quarantine
│   ├── tex1.bmp.quarantine
│   ├── d.bmp.quarantine
│   └── encrypted_payloads/
│       ├── mdE0aaiVjk.quarantine
│       ├── MsyGhIaI0X.quarantine
│       └── ... (全部 28 个加密文件)
├── stage2_cover/
│   └── picdjegdbt.exe.quarantine
├── nsis_components/
│   ├── libwin.dll.quarantine
│   ├── LetsGoogleAnalytics.dll.quarantine
│   ├── LetsGoogleAnalytics.exe.quarantine
│   ├── nsProcess.dll.quarantine
│   ├── nsExec.dll.quarantine
│   └── INetC.dll.quarantine
└── metadata/
    ├── analysis_report.md
    ├── ioc_list.csv
    └── yara_rules.yar
```

### 7.2 样本密码

建议使用标准样本库密码 `infected` 对所有 `.quarantine` 文件进行 ZIP 加密存储。

### 7.3 标签

```
tags: quickq, letsvpn, kuailian, falcon-sdk, p2cdn, dns-hijack,
      nic-control, traffic-intercept, ga4-exfil, shellcode-bmp,
      inno-setup, nsis, gvisor, silver-fox, winos4, farfli,
      go-compiled, dll-sideload, process-injection, steganography,
      anti-debug, encrypted-payload, letsgo-network, netpas
```

---

## 八、更新维护建议

### 8.1 动态样本收集

该恶意软件分发基础设施使用 PoW (工作量证明) 反爬虫保护。收集新样本需要：

1. 访问 `https://down.fx-quickq.com.cn/download.php?type=kuailian`
2. 从 `/api_get_task.php` 获取 nonce 和 difficulty
3. 计算 SHA-256 PoW (difficulty=4, 需要找到 "0000" 开头的哈希)
4. 提交到 `/api_verify.php`（需要维持 PHP Session）
5. 获取阿里云 OSS 签名 URL 下载

建议编写自动化脚本定期检查新样本。

### 8.2 关注的变种指标

- Falcon SDK 版本号变化（当前: 2025-08-26 编译）
- 新的随机目录名（当前: `uhjwxkky`, `kbyvnnp`）
- 新的加密载荷文件名模式
- 阿里云 OSS 存储桶名称变化
- P2CDN 模块版本变化（当前: `9.4.0.2185`）
- 新的 CloudFront 分发 ID

### 8.3 情报共享

建议将此分析共享至以下平台：
- VirusTotal (上传样本哈希)
- MISP (分享 IOC)
- 行业 ISAC
- CERT/CC
