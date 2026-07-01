# 样本价值优先级排序（供优先分析）

**结论先行:** 64 个样本分属 **3 个不同家族**。真正需要重点看的是 **7 个"代表样本"**；其余 40+ 个是同一 Flutter 模板的品牌换皮，边际价值低（主要用于多签名入库）。

> **重要发现:** awsdl SEO CDN 的 44 个"品牌"样本经抽样比对（nord/v2rayn/surfshark），内部是**完全相同的 Flutter 模板**（`Main.exe` + 相同 `AHAspeed`/`Cham` 图标资源，品牌间仅差 2 个图标文件），且与 `heibao` 同源。**它们与 fx-quickq 的 Falcon/douyinray 家族不是同一伙人。**

---

## 🥇 Tier S — 必看（最高价值，各不相同的核心样本）

| 优先级 | 样本 | 原始 SHA256 | 为什么最值钱 |
|--------|------|-------------|-------------|
| **1** | `fxquickq_nextgen_kuailian_win` | `b1f21f45a84d7c0b94d7fd92a12a230f9aa129c7213673cd254f42a7a30e1929` | **皇冠明珠**：主家族最新一代；Falcon SDK（DNS劫持/流量拦截/gVisor）；P2CDN 宿主进化为**抖音 douyinray7**（字节 ttnet + 键盘钩子 + Cookie/账号窃取）；PoW 保护 = 攻击者最想藏的 |
| **2** | `fxquickq_type-clash_ClashVerge_zip` | `4b91395ca4ceae702d0426b74a965c7c95ebdc7fc5651413690a0f7069258e05` | **木马化 Clash Verge 2.5.1**：用真实产品名伪装，专骗有安全意识的技术用户；PoW 保护 |
| **3** | `fxquickq_type-quickq_zip` | `32431623e22c82e1ecf7f0fe693d98b8c804d5aef9e696915a4f18b875cd5afe` | fx-quickq 第三个隐藏产品；PoW 保护；同主家族另一分支 |

## 🥈 Tier A — 各代表一个独立家族/平台（看 1 个即可代表一批）

| 优先级 | 样本 | 代表什么 | 价值点 |
|--------|------|---------|--------|
| **4** | `brand_heibao_win`（=44 个 SEO 品牌的代表） | **Flutter "AHAspeed" 家族**（独立第二团伙） | 一个样本代表全部 44 个换皮品牌；Flutter + tap0901 架构 |
| **5** | `yunyin_win` | **NSIS 家族**（daliaohengsheng 后端 / quick-q.com 前端） | 第三个独立分发渠道/打包方式 |
| **6** | `yunyin_clashverge_macos` | **唯一 macOS 样本** | 跨平台覆盖，DMG 格式 |
| **7** | `quickq_android` | **移动端代表** | Android 平台攻击面 |

## 🥉 Tier B — 家族内"威胁性最高"的换皮代表（可选看 2-3 个）

同为 Flutter 换皮，但**仿冒对象**决定威胁性——挑最能骗到人的看：
- 仿冒国际正版：`brand_nord_win` / `brand_express_win` / `brand_surfshark_win`（骗付费 VPN 用户）
- 仿冒开源工具：`brand_v2rayn_win` / `brand_ssr_win` / `brand_clash_win`（骗技术用户）

## 📦 Tier C — 批量签名素材（不必逐个看）

其余 ~40 个品牌 exe/apk：同一 Flutter 模板换皮，**逐个动态分析边际价值极低**。用途：把 `MANIFEST.csv` 里它们的 `original_sha256` 批量入库，形成多哈希检测覆盖即可。

---

## 一句话建议
**先看 Tier S 的 3 个（fx-quickq Falcon/douyinray 家族），再看 Tier A 的 4 个（heibao/yunyin/macOS/android 各代表一个独立家族/平台）——这 7 个覆盖了全部真正不同的东西。** 剩下 57 个大多是这 3 个家族的换皮/跨平台变体，批量入库即可。

## 三大家族速查
| 家族 | 代表 | 打包 | 客户端技术 | 分发 | 特征 |
|------|------|------|-----------|------|------|
| **A. Falcon/QuickQ（最危险）** | fxquickq_nextgen / quickq / clash | Inno 5.3.9 | .NET/Go + Falcon SDK | `fx-quickq.com.cn` (PoW) | DNS劫持、流量拦截、douyin P2CDN、shellcode BMP、盗证书 |
| **B. AHAspeed Flutter（换皮量产）** | heibao + 44 品牌 | Inno 6.1.0 | Flutter + tap0901 | `awsdl.com`/`awsdl.xyz` (SEO直连) | 同模板换皮 44+ 品牌 |
| **C. 云隐 NSIS** | yunyin (win/apk/dmg) | NSIS 3.11 | 待深入 | `daliaohengsheng.com` | 独立后端，含 macOS |
