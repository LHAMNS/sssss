# QuickQ / 快连 恶意样本库 — 交付说明（供分析团队）

**报告编号:** MAL-2026-0301-QUICKQ（下一代 + 大规模变体采集）
**采集日期:** 2026-07-01
**采集来源:** 直接从活跃分发基础设施在线抓取（PoW 绕过 + SEO CDN 品牌枚举 + 直连下载）
**样本总数:** **51 个去重样本**（46 Windows exe + 1 Windows zip + 3 Android apk + 1 macOS dmg）
**关联分析:** 见仓库根目录 `analysis_report.md`
**完整清单:** 见本目录 `MANIFEST.csv` / `MANIFEST.json`
**分发站点情报:** 见本目录 `distribution_sites.json`

---

## ⚠️ 安全警告与双重中和（务必先读）

本目录所有 `.zip` 均为**真实、可运行的恶意软件样本**。已做**双重中和**：

1. **加密压缩包**：所有样本封装在密码 ZIP 内，**密码统一为 `infected`**（恶意软件研究行业标准）。压缩状态下无法执行，且可绕过传输途中杀软自动删除。
2. **文件头破坏（defang）**：解压后得到的样本文件，其**前 4 个字节已被清零**（`00 00 00 00`），破坏了 PE 的 `MZ` 魔数 / ZIP/APK 的 `PK` 魔数 / DMG 头，**使其绝对无法被双击运行或被安装器识别**。

> **除非在可信隔离环境中手动恢复文件头，否则样本不可能运行。** 每个样本原始的前 4 字节记录在 `MANIFEST.csv` 的 `defang_restore_first4_hex` 列。

### 恢复与分析流程（仅限隔离沙箱/断网虚拟机）
```bash
# 1. 解压（密码 infected）
unzip -P infected brand_quickq_win_DEFANGED.zip
# 2. 查 MANIFEST.csv 得到该样本 defang_restore_first4_hex，例如 PE 为 4d5a9000
# 3. 恢复前 4 字节（Linux 示例，把 4d5a9000 写回文件开头）:
printf '\x4d\x5a\x90\x00' | dd of=<解压出的文件> bs=1 count=4 conv=notrunc
# 4. 校验：恢复后文件 SHA256 应等于 MANIFEST.csv 中 original_sha256
sha256sum <文件>
```
常见魔数参考：PE(exe)=`4d5a9000`(即 MZ..) · ZIP/APK=`504b0304`(PK..) · 分卷重组后的 zip 同理。

### 分卷文件（超过 GitHub 100MB 的样本）
个别大样本被切分为 `*.zip.part00`, `*.zip.part01`，先重组再按上述流程处理：
```bash
cat <name>_DEFANGED.zip.part* > <name>_DEFANGED.zip
unzip -P infected <name>_DEFANGED.zip
```

---

## 一、采集范围与家族结论

本次从**活跃分发基础设施**实时采集，覆盖 3 个层级：

| 层级 | 分发机制 | 站点/后端 | 样本 |
|------|---------|----------|------|
| **A. 主家族（最高价值）** | PoW 反爬 → 阿里云 OSS 签名链接 | `down.fx-quickq.com.cn` | 下一代 QuickQ（`type=kuailian`）+ 第二产品（`type=quickq`） |
| **B. SEO 投毒 CDN** | 直连下载 | `www.awsdl.com` / `cdn.awsdl.xyz` | **44 个仿冒品牌**（每个 Windows exe + Android apk） |
| **C. 独立后端** | 直连下载 | `s3.daliaohengsheng.com`（`quick-q.com` 前端） | 云隐 exe/apk + 木马化 ClashVerge (macOS) |

**关键结论：**
- **B 层是一个大规模 SEO 投毒行动**：用同一套 Inno Setup 6.1.0 生成器，批量伪装成 **44 个知名 VPN/代理品牌**（含仿冒国际正版：NordVPN、ExpressVPN、Surfshark、CyberGhost、IPVanish、Astrill，以及 Clash/V2rayN/Shadowrocket/SSR/Hiddify 等开源工具，和快连/黑豹/西瓜/迅游/猎豹等国产品牌）。**44 个样本哈希两两不同**（每个品牌独立构建），是极佳的多签名检测素材。
- **A 层是主家族最新一代**：P2CDN 僵尸宿主已从"快手"(`pcdnacc7`) 进化为"抖音"(`douyinray7`)，内含字节跳动 `ttnet` + 输入钩子 + Cookie/账号窃取。详见根目录 `analysis_report.md` 与下方 §三。
- **同一伙人的证据**：主家族下一代与已归档 v1 的 **NSIS 掩护安装器哈希完全一致**（`22944c87…`），2 个 shellcode BMP（`d.bmp`/`tex1.bmp`）哈希完全一致，签名主体均为 `LetsGo Network Incorporated` / `devel@letsgo-network.com`。

---

## 二、样本清单（摘要，完整见 MANIFEST.csv）

### 2.1 主家族（PoW 保护，最高价值）
| 样本 | 原始 SHA256 | 说明 |
|------|-------------|------|
| `fxquickq_nextgen_kuailian_win` | `b1f21f45a84d7c0b94d7fd92a12a230f9aa129c7213673cd254f42a7a30e1929` | 下一代，Inno 5.3.9，douyinray7 P2CDN |
| `fxquickq_type-quickq_zip` | `32431623e22c82e1ecf7f0fe693d98b8c804d5aef9e696915a4f18b875cd5afe` | fx-quickq 第二产品（type=quickq） |

### 2.2 SEO CDN 仿冒品牌（44 个，Inno 6.1.0，全部哈希互异）
```
astrill biubiu clash clashx clashx-meta cyberghost express feimao feiniao feiyu
flclash fox green haitun heibao hiddify ipvanish karing kuailian ladder lantern
liebao loon nekoray nord panda potatso quickq qv2ray rocket shadowrocket shandian
skyline ssr streisand surfshark surge turbo v2rayn v2rayng whale xigua xunyou yunfan
```
（各品牌 Windows exe 哈希见 MANIFEST.csv；下载 URL 形如
`https://www.awsdl.com/download/3rdparty/seo/<brand>/<brand>_win.exe`）

### 2.3 跨平台变体（不同样本类型）
| 样本 | 平台 | 说明 |
|------|------|------|
| `quickq_android` / `heibao_android` / `yunyin_android` | Android APK | 移动端变体 |
| `yunyin_clashverge_macos` | macOS DMG | 木马化 ClashVerge |
| `yunyin_win` | Windows | NSIS 3.11（daliaohengsheng 后端） |

---

## 三、下一代 vs 已归档 v1 演进对比

| 组件 | v1（2026-02） | v2 下一代（2026-05-17） |
|------|--------------|------------------------|
| 载荷目录 | `uhjwxkky/`、`kbyvnnp/` | `cgqrrrdqh/`、`dbwpf/` |
| **P2CDN 宿主** | `pcdnacc7.exe`（快手/网易 PCDN，盗用 Rockstar 证书） | **`douyinray7.exe`（抖音/字节跳动）** |
| P2CDN 技术栈 | 网易 PCDN | **字节 `ttnet_wrapper` + `tray_douyin` + Lynx + Electron** |
| 新增窃密 | — | `global_input_hook_manager`（键盘钩子）、`cookie_manager`、`account_manager` |
| NSIS 掩护安装器 | `picdjegdbt.exe` `22944c87…` | `xiisieufjvs.exe` `22944c87…`（**相同**） |
| `d.bmp` / `tex1.bmp` | `f861cbed…` / `3628b4d6…` | **完全相同** |

---

## 四、建议的团队后续动作
1. 隔离沙箱内解压（密码 `infected`）→ 按 §安全警告 恢复文件头 → 校验 `original_sha256` → 动态分析。
2. 将 `MANIFEST.csv` 全部 `original_sha256` 入病毒库（参考 `virus_sample_library_guide.md`）。
3. 将 `distribution_sites.json` 域名/URL 及 `awsdl.com`/`awsdl.xyz`/`daliaohengsheng.com` 后端加入防火墙黑名单。
4. 重点监控 **PoW 保护站点 `fx-quickq.com.cn`**（承载最新一代 douyinray），并对 `awsdl` SEO CDN 做品牌枚举持续监控（新品牌=新前端站点）。
5. 针对下一代 `douyinray7.exe` 抖音宿主 + 输入钩子/Cookie 窃取模块补充检测规则。
