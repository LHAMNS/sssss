# 扩大侦察情报（第二轮 · 其他类型/其他家族）

**日期:** 2026-07-01 | **方法:** 3 个并行侦察代理（HEAD/range 验证，威胁情报 OSINT），只拉取新家族/新诱饵代表样本。

---

## 一、新诱饵品类（已入库代表样本）

awsdl PPI CDN 不止投毒 VPN，还扩展到**游戏玩家 / 聊天用户**（同一 AHAspeed Flutter 家族换诱饵主题）：

| 样本 | 诱饵 | 原始 SHA256 |
|------|------|-------------|
| `lure_minecraft_win` | Minecraft（游戏） | `23f812d2b3aa3ce8d8e1ebc00be69d27b35cbea4ee45eb4603d7aba258057b56` |
| `lure_genshin_win` | 原神（游戏） | `6b39bc2cdc0a5a67d96259dcd23e05cfc6878f0cd899adba57e7311b3d054e3e` |
| `lure_discord_win` | Discord（聊天） | `6b3d942cd70e77de4a034eaed8d2109c2403b3814f7a152cafd8620c0886ec07` |

**同类未逐个入库（同家族换皮，URL 见下）:** csgo、lol、pubg（各 win.exe+apk，`www.awsdl.com/download/3rdparty/seo/<name>/`）。经抽样确认：`Main.exe`(Flutter)+`tap0901`+`AHAspeed/Cham` 图标，与 44 个 VPN 品牌是同一模板。

---

## 二、新分发基础设施（加入封禁）

- **`dl2.awsdl.com`** — www.awsdl.com 的**完整镜像后端**（同 Cloudflare IP，字节级相同载荷）。
- **`cdn.awsdl.xyz`** — 302 重定向器 → www.awsdl.com（非独立后端）。
- **`hideyun.com`** — quick-q.com 的 iOS 诱饵/引流域名（`/download/ios` 跳转）。
- **`awsdl.xyz` "pojieban（破解版）"集群 ~26 域名** — 疑似**破解软件诱饵**（新品类）：ipojiebanvpn.com、ipojiebanjichang.com、ipojiebanfanqiangjiasuqi.com、imianfeijichang.com、ihaoyongvpn.com 等。
- **更大 PPI 网络边缘/重定向器:** ranqigaibiao.com（wtcn2/4/6/7/11/13、cwtcn6）、jsqcn.net（cn5/cn8/cn98/user1、api.ahajsq.net）、ahajsq.com、cham666.com、aha666.com、shortapp.net、hellocham.com、ahaspeed.com。
- **同 CDN 的 VPN 落地域名（部分）:** vpnjs.net、qingwavpn.com、dengtavpn.net、qihaovpn.com、chamvpn.com、xkboxvpn.com、diandianvpn.com、chaoshenvpn.com、shanyangvpn.com、ahaspeedvpn.com、heibaovpn.com、kuaiquvpn.com。

---

## 三、威胁归因（OSINT）

本操作处于中国"翻墙"假/破解 VPN 生态中，与 **Silver Fox / Void Arachne / AtlasCross RAT（SwimSnake / UTG-Q-1000）** 高度关联——同一"假 VPN"诱饵主题被用于投递 RAT。

**同团伙/关联的其他诱饵品类（RAT 线）:**
- 加密货币：假 Trezor（trezor-trezor.com）
- 加密聊天：Signal、Telegram、CloudChat、WWTalk
- 协作/远控：Zoom、MS Teams、UltraViewer、ToDesk、WPS
- 其他：木马化医疗软件、假税务 PDF、被滥用的国产 RMM、伪装 WhatsApp 的 Python stealer
- 关联恶意家族：ValleyRAT、Winos 4.0、Gh0st RAT 衍生、Farfli、BlackMoon

**关键参考:** Hexastrike《Trust the Tunnel, Get the Trojan》(Atlas RAT via 假 VPN 安装器)、The Hacker News 2026-03 (AtlasCross)、Cyble/CyberInsider (木马化 LetsVPN→Winos 4.0)、Microsoft Storm-2561 (SEO 投毒假 VPN 窃密)。

---

## 四、三家族 → 生态全景（更新）

| 家族/集群 | 代表 | 分发 | 说明 |
|-----------|------|------|------|
| **A. Falcon/QuickQ（最危险）** | fx-quickq nextgen/quickq/clash | fx-quickq.com.cn (PoW) | Falcon SDK、DNS劫持、抖音 douyinray P2CDN、盗证书 |
| **B. AHAspeed Flutter（量产换皮）** | heibao + 44 VPN品牌 + 游戏/Discord | awsdl.com / dl2.awsdl.com / awsdl.xyz | 同 Flutter 模板，诱饵覆盖 VPN+游戏+聊天 |
| **C. 云隐 NSIS** | yunyin (win/apk/dmg) | daliaohengsheng.com（quick-q.com 前端）| 独立后端，含 macOS + iOS 引流 hideyun.com |
| **D. 破解软件集群（待取样）** | awsdl.xyz "pojieban" ~26 域名 | awsdl.xyz | 破解版诱饵，疑同 PPI 网络 |
| **E. Silver Fox RAT 线（外部情报）** | AtlasCross/ValleyRAT/Winos4.0 | 假 Zoom/Signal/Teams/Trezor 等 | 同"假软件"诱饵主题的 RAT 投递 |

---

## 五、下一步可选（未做，等确认）
1. 取样破解软件集群（awsdl.xyz "pojieban"）代表，确认是否新载荷家族。
2. 抓取 awsdl 更多真实 VPN 品牌（ahaspeed/cham/qingwa/dengta…）——但预计仍是家族 B。
3. 按 Silver Fox 报告 IOC 拉取 AtlasCross/ValleyRAT 样本做交叉比对（需报告附录哈希）。
