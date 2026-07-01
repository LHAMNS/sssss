# 幕后团伙归因分析（谁在运营 / 是不是同一个人）

**报告编号:** MAL-2026-0301-QUICKQ · **日期:** 2026-07-01
**方法:** 2 个并行代理做基础设施关联(WHOIS/NS/托管/ASN) + 团伙身份 OSINT(App Store 发行方/公司注册/GitHub)。
**核心结论:** **不是同一个人。** 这是一个**竞争性的中国"翻墙/加速器"灰产生态,至少 4 个相互独立的运营方**,外加一个**寄生其上、冒用这些品牌**的 APT(Silver Fox)。

> ⚠️ 环境局限:本沙箱出口网关拦截了 443 的 TLS,证书 SAN 比对失效(全被替换为 Anthropic 网关证书);WHOIS 走网页查询。身份主要靠 App Store 发行方、公司注册、GitHub 元数据佐证——较强但正式报告建议再用付费 WHOIS-history + crt.sh 复核。

---

## 一、运营方清单（谁是谁）

| 集群 | 运营主体 | 国家/地区 | 模式 | 关系判定 |
|------|---------|----------|------|---------|
| **A-快连/LetsVPN** | **LetsGo Network Inc.**(加拿大,董事 **Hong Lei**)+ **LETSGO NETWORK PTE. LTD.**(新加坡 202133733H) | 加/新 | 自研原生客户端(Falcon/TUN 栈) | 独立;与 QuickQ、B 均为竞争对手 |
| **A-QuickQ** | **HongKong IRAY Technology Co. Ltd**(IRAY Mobile,js7.io) | 香港 | 自研客户端 | **与 LetsGo 是两家不同公司** |
| **B-AHAspeed(啊哈加速器)** | **M LIFESTYLE TRADING INC.**(iOS 发行方,`net.ahajs`) | 离岸/中 | 真实灰产 VPN + PPI 投毒 | 与 Cham 同一运营方 |
| **B-Cham(茶VPN)** | hellocham.com;**`cham_114.ahaspeed.com` 返回 200** | 离岸/中 | 姊妹品牌 | **= AHAspeed(共享基础设施,铁证)** |
| **B-awsdl PPI CDN** | 未具名(运营方自己把 "cham/jsq888/awsdl" 并列) | 离岸(Cloudflare 门控) | PPI/联盟分发 CDN | **B 的分发层** |
| **C-云隐(yunyin)** | daliaohengsheng.com / quick-q.com / hideyun.com | 阿里云-中/离岸 | NSIS 加载器 | **碎片化;加载器后端并入 RAT 线基础设施** |
| **RAT线-Silver Fox** | APT(Void Arachne/SwimSnake/UTG-Q-1000);盗用 **DUC FABULOUS CO.,LTD**(河内)证书 | 中国背景 | 冒牌 typosquat + 自建 C2 | **独立冒用品牌者(非运营方、非 PPI 客户)** |

**关键人名/实体:** Hong Lei(LetsGo 董事,加拿大)· **jason-xie / jason-xie-123**(GitHub,**新加坡**——与 LetsGo 新加坡实体吻合,LetsVPN/Falcon SDK 工程师)· LetsGo Network Inc.(加)· LETSGO NETWORK PTE. LTD.(新)· HongKong IRAY Technology Co. Ltd · M LIFESTYLE TRADING INC.(AHAspeed)· DUC FABULOUS CO.,LTD(被盗证书,Silver Fox 使用)· Taiyuan Lihua Near Information Technology(Storm-2561 证书,**排除**)。

---

## 二、跨家族最强关联线索

**`share-dns.com / share-dns.net` 域名服务器(注册商 Gname.com)**——唯一跨越集群边界的基础设施指标:
- 串起 **家族 A(`fx-quickq.com.cn`)+ 家族 C(`daliaohengsheng.com`)+ RAT 线(`quickq-quickq.com`、`bifa668.com`)**
- 实例级最紧密:**`a10.share-dns.com / b10.share-dns.net` + Gname 把家族 C 的云隐加载器后端(daliaohengsheng)直接绑到 Silver Fox 的 `quickq-quickq.com`**
- **家族 B 从不碰 share-dns**——全部独立在 Cloudflare(NS 对 `betty+chad` / `jean+damiete`),自成体系

> 解读:share-dns/Gname 更像一个**被多方共用的托管 DNS/防失联服务 nexus**,而非"同一个终端运营方"。它是横跨 A/C/RAT 的那根线,但不足以判定 A=C=RAT 是同一人。

---

## 三、逐对关系判定

1. **A ↔ B:不同运营方(置信 中高)**
   - 工程模式完全不同:A 自研原生客户端(jason-xie 的 Go TUN/gvisor netstack + 自研安装器栈=Falcon SDK);B 是 Flutter 套 `tap0901` 的量产换皮 + PPI 喷洒
   - 命名空间/基础设施不同:`world.letsgo.*`/letsvpn.world vs `net.ahajs`/`com.hellocham`/awsdl.com
   - 无共享 NS/IP/ASN;仅有的重合是通用"快连/翻墙"主题 + "666"幸运数字习惯(Cham666 & LetsGo666)——均为**弱信号**,不构成同源

2. **A 内部:LetsVPN ≠ QuickQ(两家竞争公司)**
   - 不同法人(加/新 LetsGo vs 香港 IRAY)、不同包名(`world.letsgo.*` vs `work.js7.*`)、不同下载设施(letsvpn.world vs js7.link/js66.site)
   - "快连"是被多个品牌通用的中文词,是此前混淆的根源;按发行方/包名数据能干净区分

3. **B 内部:AHAspeed = Cham(同一运营方,置信 高)**
   - 铁证:`cham_114.ahaspeed.com` 返回 200(Cham 内容跑在 AHAspeed 自己域名上);运营方博客把 "cham/jsq888/awsdl" 并列;awsdl 是其自有 PPI CDN

4. **C:碎片化——并入 RAT 线而非 B(置信 中)**
   - `daliaohengsheng.com`(云隐加载器后端)与 RAT 域 `quickq-quickq.com` **共用同一 share-dns 实例 + 同一 Gname 注册商 + 阿里云托管** → 把 C 绑到 Silver Fox 基础设施,**不并入 B**,与 A 只有一根细的 share-dns 线

5. **Silver Fox:独立冒用品牌的 APT(置信 高)**
   - 自建专用 C2 `bifa668.com`(2025-10-27 注册,韩国 61.111.250.139,TCP **9899** 拉二阶段)——**直连 C2,非第三方 PPI**
   - typosquat 冒牌投递(`quickq-quickq.com`、`www-surfshark.com`、`signal-signal.com`)+ 盗用 EV 证书(DUC FABULOUS)——与 awsdl/AHAspeed/Cham/LetsGo/IRAY **零重合**
   - 载荷是 AtlasCross/ValleyRAT/Winos 间谍 RAT;它是**冒用 QuickQ 品牌**去钓中文用户,既非 QuickQ 运营方,也非 B 的 PPI 客户

---

## 四、一句话总结
**背后不是同一个人**:A(LetsVPN=LetsGo 加/新;QuickQ=香港 IRAY,二者互为竞品)、B(AHAspeed=Cham,M LIFESTYLE 运营,自带 awsdl PPI)是**各自独立的灰产 VPN 运营方**;C(云隐)是碎片化的加载器节点,其后端并入了 Silver Fox 的 share-dns 基础设施;Silver Fox/AtlasCross 是**独立 APT**,寄生式冒用上述所有品牌投递 RAT。唯一横向线索是被 A/C/RAT 共用的 **share-dns/Gname 托管 DNS nexus**。

## 五、建议团队复核动作
1. crt.sh 证书透明度 + 付费被动 DNS(从非拦截出口)恢复真实 SAN/历史 A 记录,验证 share-dns nexus 的真实归属。
2. 追 Gname 注册商下 `a10/b10.share-dns` 所辖域名全集(可能揭示 Silver Fox 更多 C2/投递域)。
3. 关注 eSentire "Kong RAT" 报告(直接点名 QuickQ/LetsVPN/quickq-cn.com/香港阿里云 OSS)——家族 A 相关的独立命名活动。

## 来源(节选)
eSentire(Kong RAT/QuickQ)· Hexastrike & The Hacker News 2026-03(Silver Fox/AtlasCross,bifa668:9899)· Cyble/CyberInsider(木马化 LetsVPN→Winos4.0)· Malwarebytes 2025-09 & Cyfirma(AHAspeed/假 VPN)· Apple iTunes Lookup API(发行方/包名)· 加拿大/新加坡公司注册 · GitHub(LetsgoNetwork/LetsGo666、jason-xie-123、QuickQVPN)· who.is/Google DoH/ipinfo。
