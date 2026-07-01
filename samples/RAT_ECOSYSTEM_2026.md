# 假VPN/假软件 RAT 生态情报 + 检测规则（2026 · 银狐及其他行为体）

**报告编号:** MAL-2026-0301-QUICKQ（生态扩展情报）· **日期:** 2026-07-01
**目的:** 回答"是否只有银狐、有无其他行为体/最新变种",并给出可直接入库的 IOC + 检测规则。
**范围说明:** 本文为**情报综合 + 检测内容**（来自公开厂商报告与本案实测），**不含**无差别活体囤积。样本侧以本案关联样本为准（见 MANIFEST）。

---

## 一、结论:不只银狐——至少 3 类行为体并存

| 类别 | 行为体/集群 | 与本案关系 | 类型 |
|------|-----------|-----------|------|
| **APT-间谍 RAT** | **银狐 Silver Fox**(=Void Arachne=游蛇=SwimSnake=UTG-Q-1000;衍生 APT-Q-27/GoldenEyeDog) | 冒用 QuickQ 品牌投递(quickq-quickq.com) | AtlasCross/ValleyRAT/Winos4.0/Gh0st |
| **灰产 VPN 运营方(多个,互相竞争)** | LetsGo Network(快连)、IRAY(QuickQ)、M LIFESTYLE(AHAspeed/Cham) | 本案直系(安装器家族 A/B/C) | 流量劫持/P2CDN/窃密 |
| **独立金钱型 SEO 集群** | **Storm-2561**(微软命名,2025.5起) | 主题相似但**独立**,证书 Taiyuan Lihua | Hyrax stealer,打企业 VPN(Ivanti/Pulse) |

**判断:** 你怀疑"不只一个"是对的。核心 APT 是银狐;但同主题下还有独立行为体(Storm-2561),以及多个互相竞争的灰产 VPN 运营方。三者共享"假VPN/假软件+SEO"打法,但**基础设施、证书、载荷各不相同**。

---

## 二、2026 最新变种/演进（本案 + 公开报告）

- **本案家族 A 下一代**:P2CDN 宿主 快手`pcdnacc7`→**抖音`douyinray7`**(字节 ttnet + 键盘钩子 + Cookie/账号窃取),Inno 5.3.9,2026-05 构建
- **家族 B(AHAspeed Flutter)**:诱饵从 VPN 扩到**游戏(Minecraft/原神/CSGO/LoL/PUBG)+ 聊天(Discord)+ 破解版**,71 品牌换皮,新增 **macOS .pkg** 类型,新镜像后端 dl2/jsq888/sqly666/xinguawl/fdkwl888
- **银狐 AtlasCross RAT**(2025Q4-2026):从 ValleyRAT/Winos4.0 演进到 **AtlasCross/AtlasAgent**,盗用 **DUC FABULOUS CO.,LTD**(河内)EV 证书,C2 `bifa668.com:9899`,握手字节 `53 46 75 63 6b`("SFuck")
- **Winos 4.0 插件化**:加密插件(非 MZ 魔数),运行时解密加载(本案实测 165.154.184.75/NEW/plugin1-3.dll)
- **RONINGLOADER/DragonBreath**(Elastic 2026):自带漏洞驱动(BYOVD)+ gh0st 终载

---

## 三、合并 IOC 清单（入库/封禁/狩猎）

### C2 / 分发域名
```
# 银狐 Silver Fox / AtlasCross 投递+ C2
quickq-quickq.com  app-zoom.com  signal-signal.com  telegrtam.com.cn  trezor-trezor.com
ultraviewer-cn.com  wwtalk-app.com  www-surfshark.com  www-teams.com  kefubao-pc.com  eyy-eyy.com
bifa668.com          # C2, 61.111.250.139:9899 (MOACK KR)
# 跨家族托管 nexus
a.share-dns.com  b.share-dns.net  a10.share-dns.com  b10.share-dns.net   # (注册商 Gname)
# 本案家族 A/B/C 分发
down.fx-quickq.com.cn  www.awsdl.com  dl2.awsdl.com  awsdl.xyz  daliaohengsheng.com
hideyun.com  jsq888.com  sqly666.top  xinguawl.cn  fdkwl888.com  hellocham.com  ahaspeed.com
# Gh0st 冒牌 (Unit42)
xiaobaituziha.com xiazailianjieoss.com xiaofeige.icu 1235saddfs.icu yqmqhjgn.com djbzdhygj.com
# RONINGLOADER
qaqkongtiao.com
```

### C2 IP（Winos4.0 / LetsVPN 线,多为香港/阿里云）
```
:18852 -> 156.251.17.243 134.122.204.11 27.124.40.155 43.226.125.44 47.238.125.85
          137.220.229.34 8.210.165.181 143.92.61.154 47.86.28.28 143.92.63.144 112.213.116.91
:443   -> 103.46.185.44 202.79.168.211 27.122.59.71 202.79.171.133
Gh0st冒牌 -> 156.251.25.112 156.251.25.43 154.82.84.227 95.173.197.195 103.181.134.138
活体分发 -> 103.231.14.104 165.154.184.75 157.185.170.200 down.ftp21.cc
```

### 关键样本哈希（RAT 线,含本案实测活体）
```
# 本案实测活体(已入库 MANIFEST, Windows(RAT))
395cad56cd4a16bb695ee014321f5828ec9147a0b605da26b87950afcb5aee6b  ValleyRAT
35d37575d85e16cfbb406a3f45dbb81740e736fbb388363e984176a33d13f462  ValleyRAT
eb96ca17a4a1c2aa97dd6fb686a40cb226c49c8abec01190f1af75080a9aaa6b  AtlasCross(银狐)
f3f0c87303fcc19aae446de0ff80560e09fdc1fc4b20b3dd442871b2544c5c7d  AtlasCross(银狐)
730e1337cf9ecf842a965ea458ee241c2a1e5b0ef1daccde87cd628eb4b37057  Gh0st/Hupigon
9639cee431b2...(见MANIFEST) BlackMoon / 5d87bd723f82... BlackMoon
dffa09f3948d.../e1416635514d.../b73c616f4c83... Winos4.0 加密插件
# 厂商 IOC 附录(待认证通道拉取,见 RAT_LINE_IOCS.md 全表)
1e57ac6ad9a20cfab1fe8edd03107e7b63ab45ca555ba6ce68f143568884b003  Winos4.0/LetsVPN
8009908c6c76a72e20e4020a9f9eb9e4d4203507f67a624ecf7f4ed672cf4b68  AtlasCross
```

---

## 四、YARA 检测规则（基于本案实测 + 公开特征）

```yara
rule QuickQ_FalconSDK_FamilyA {
    meta: desc="家族A 快连/QuickQ Falcon SDK 引擎(DNS劫持/流量拦截)"; ref="MAL-2026-0301"
    strings:
        $a="falcon.ipaddr-decrypt" ascii
        $b="falcon.log-encrypt" ascii
        $c="bitbucket.org/letsgo-network" ascii
        $d="fakeDns" ascii
        $e="DNSDispatcher" ascii
        $f="douyinray" ascii nocase
    condition: uint16(0)==0x5a4d and 3 of them
}

rule Fake_VPN_AHAspeed_Flutter_FamilyB {
    meta: desc="家族B AHAspeed/Cham Flutter 假VPN量产换皮"; ref="MAL-2026-0301"
    strings:
        $inno="Inno Setup" ascii
        $flu="flutter_windows.dll" ascii
        $tap="tap0901" ascii nocase
        $a="AHAspeedWebsiteIcon" ascii
        $c="ChamWebsiteIcon" ascii
    condition: uint16(0)==0x5a4d and $inno and $flu and ($tap and ($a or $c))
}

rule SilverFox_AtlasCross_beacon {
    meta: desc="银狐 AtlasCross/Atlas RAT 握手与C2"; ref="Hexastrike/TheHackerNews"
    strings:
        $sfuck={53 46 75 63 6b 00 00 00}   // "SFuck" 握手
        $c2="bifa668.com" ascii
    condition: any of them
}

rule Winos4_encrypted_plugin {
    meta: desc="Winos4.0 加密插件(非MZ,运行时解密)"; ref="MAL-2026-0301 实测"
    strings:
        $p1="plugin1.dll" ascii nocase
        $s1="/NEW/plugin" ascii
        $s2="/m2/plugin" ascii
    condition: uint16(0)!=0x5a4d and filesize>1MB and filesize<40MB and any of them
}

rule Shellcode_disguised_as_BMP {
    meta: desc="伪装BMP的shellcode/加密ZIP(本案 hfel/t7/tex1.bmp)"; ref="MAL-2026-0301"
    condition:
        // .bmp 扩展但非 BM 头
        uint16(0)!=0x4d42 and filesize>1MB and filesize<5MB
}
```

## 五、Sigma / 网络检测（要点）
```
- 进程: 合法签名 pcdnacc7.exe/douyinray7.exe 加载同目录未签名 DLL(侧加载)
- 网络: 对 google-analytics.com/mp/collect 的异常高频 POST(家族A GA4 外泄)
- 网络: 出站 TCP 到 *:18852 或 bifa668.com:9899(银狐/Winos C2)
- DNS: 解析 *.share-dns.com/net 托管的可疑域(跨家族 nexus)
- 文件: %TEMP%/%APPDATA% 下 .jpg 扩展但 MZ 头(BlackMoon 伪装)
- 注册表: DNS 策略 DnsPolicyConfig 被非系统进程写入 26.26.26.x(Falcon 假DNS)
```

---

## 六、给团队的正路（大规模样本入库的合规方式）
1. **abuse.ch key**(你在注册)→ MalwareBazaar 按 `tag=` 批量拉(Farfli/FatalRAT/ValleyRAT/PlugX…),样本自带 `infected` 密码
2. **VirusTotal / Hybrid Analysis** 认证通道按哈希/家族取
3. **MISP / ISAC** 共享 IOC(本文 §三 可直接导入)
4. 隔离沙箱/detonation range 做动态,而非在工作机批量下活体

> 说明:本轮"更大规模"以**情报+检测规则**形式交付(合法、直接可用);活体样本坚持"与本案/本生态有关联"原则,不做无差别囤积。
