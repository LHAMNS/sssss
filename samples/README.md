# QuickQ / 快连 恶意样本包 — 交付说明（供分析团队）

**报告编号:** MAL-2026-0301-QUICKQ（下一代样本增补）
**采集日期:** 2026-07-01
**采集来源:** 直接从活跃分发基础设施在线抓取（PoW 绕过 + 直连下载）
**关联分析:** 见仓库根目录 `analysis_report.md`

---

## ⚠️ 安全警告（务必先读）

**本目录中的所有 `.zip` 均为真实、可运行的恶意软件样本。**

- 所有样本已用**加密压缩包**中和，**压缩包密码统一为 `infected`**（恶意软件研究行业标准）。
- **压缩状态下无法执行**，且可绕过传输途中被杀毒软件自动删除/隔离。
- **仅可在隔离沙箱 / 断网虚拟机中解压和分析**，切勿在生产主机上解压运行。
- 解压后得到的 `.exe` 需要管理员权限运行（`requireAdministrator`），一旦运行会立即释放载荷。

---

## 一、样本清单与校验

### 1.1 主样本：下一代 QuickQ 投放器（v2 / 下一代）

| 项目 | 值 |
|------|-----|
| 文件 | `QuickQ_nextgen_v2_20260517_INFECTED.zip.part00` + `.part01`（分卷） |
| 压缩包密码 | `infected` |
| 外层 ZIP SHA256 | `0c565f15d8d0bd9baedca81c6dded0e13d814b4403787ba5ccd0848a34812dbc` |
| 内层安装器 `jF8DjkVjVJS.exe` SHA256 | `b1f21f45a84d7c0b94d7fd92a12a230f9aa129c7213673cd254f42a7a30e1929` |
| 大小 | 106,740,388 bytes (~101.8 MB) |
| 打包器 | Inno Setup 5.3.9 (Unicode) |
| 内部构建日期 | 2026-05-17 |
| 分发站点 | `https://down.fx-quickq.com.cn/download.php?type=kuailian` |
| 分发 OSS | `fvjifek.oss-accelerate.aliyuncs.com`（AccessKey `LTAI5tDVr1AeszcfPizjSxiP`） |

> **分卷重组说明（GitHub 单文件 100MB 限制所致）：**
> ```bash
> # Linux/macOS:
> cat QuickQ_nextgen_v2_20260517_INFECTED.zip.part* > QuickQ_nextgen_v2.zip
> # Windows PowerShell:
> cmd /c copy /b QuickQ_nextgen_v2_20260517_INFECTED.zip.part00+QuickQ_nextgen_v2_20260517_INFECTED.zip.part01 QuickQ_nextgen_v2.zip
> # 重组后校验（应等于下值）:
> #   5bb23f13ee60fcb24b1cf67fda1dec89c4ad90964f01dfb5bec07436c29a0c82
> # 然后用密码 infected 解压
> unzip -P infected QuickQ_nextgen_v2.zip
> ```

### 1.2 变体样本（同期在线抓取的其它品牌/渠道）

| 文件（`_INFECTED.zip`，密码 `infected`） | 内层 EXE SHA256 | 大小 | 打包器 | 来源 |
|------|------|------|------|------|
| `variant_QuickQ-variant_yunyin-云隐_NSIS311` | `5f89011ea449f0ecff9f0961d6c58e3e5573ce9868cc39bb2ce31b86c332bb85` | 27.8 MB | NSIS 3.11 | `quick-q.com` → `s3.daliaohengsheng.com/yunyin_v1.7.6.exe` |
| `variant_QuickQ-variant_heibao-黑豹_Inno610_Flutter` | `d4144904b6b317e7effd2847a9d28d7a84d667ebf334a628b29ad9a82a2501a7` | 53.6 MB | Inno Setup 6.1.0 | `fastquickq.com` → `cdn.awsdl.xyz/.../heibao/heibao_win.exe` |
| `variant_QuickQ-variant_quickq-awsdl_Inno610` | `5cb99819c866602d2320c75409e983b057cf511968ff8d0c3dfa0f4c457c677c` | 53.4 MB | Inno Setup 6.1.0 | `bestquickq.com`/`quickqvpn.net` → `www.awsdl.com/.../quickq/quickq_win.exe` |

---

## 二、下一代样本 vs 已归档 v1 的演进对比

| 组件 | v1（已归档，2026-02） | v2 下一代（本次，2026-05-17） |
|------|----------------------|------------------------------|
| 载荷目录名 | `uhjwxkky/`、`kbyvnnp/` | `cgqrrrdqh/`、`dbwpf/`（随机化） |
| **P2CDN 宿主** | `pcdnacc7.exe`（快手 Kuaishou / `ku` 命名空间，盗用 Rockstar 证书） | **`douyinray7.exe`（抖音 / 字节跳动 ByteDance）** |
| P2CDN 技术栈 | 网易 PCDN (`163.com`) | **字节 `ttnet_wrapper` + `project\tray_douyin\` + Lynx + Electron** |
| 数据窃取组件 | — | `global_input_hook_manager`（输入钩子/键盘记录）、`cookie_manager`、`account_manager` |
| NSIS 掩护安装器 | `picdjegdbt.exe` (`22944c87…`) | `xiisieufjvs.exe` (`22944c87…`) — **哈希完全相同** |
| Shellcode `d.bmp` | `f861cbed…` | `f861cbed…` — **哈希完全相同** |
| Shellcode `tex1.bmp` | `3628b4d6…` | `3628b4d6…` — **哈希完全相同** |
| Shellcode `hfel.bmp`/`t7.bmp` | （v1 哈希） | 更新（`df7c6a82…` / `8500ffcf…`） |
| 签名主体 | LetsGo Network Incorporated | LetsGo Network Incorporated（未变，`devel@letsgo-network.com`） |

**结论：** 下一代与 v1 属**同一家族**（NSIS 掩护安装器与 2 个 shellcode BMP 哈希完全一致），核心演进是把 P2CDN 僵尸宿主从**快手**换成了**抖音**品牌，并显式集成了输入钩子与 Cookie/账号窃取模块。

### 下一代 v2 内层组件完整哈希

```
b1f21f45a84d7c0b94d7fd92a12a230f9aa129c7213673cd254f42a7a30e1929  jF8DjkVjVJS.exe (外层Inno安装器)
4d433dc52d7117e2c1a2c7850363a30794c91688a1c557e5873af1636c9870d2  cgqrrrdqh/douyinray7.exe (抖音P2CDN宿主)
22944c87ac71fc5a95198fe0b4ed51f9d8ae1759d5b840ba18c9e9f26902754a  dbwpf/xiisieufjvs.exe (LetsVPN NSIS掩护, 同v1)
df7c6a82b825dca4559ffb6931e4868484988ca7aa3e50bd81e8fa04dd63290d  cgqrrrdqh/hfel.bmp (shellcode)
8500ffcfb18591354bf4866b84f1b7d6b342787bd99640f5fe1a9136ed352513  cgqrrrdqh/t7.bmp (shellcode)
3628b4d6879b91c4b5f4ddeb7ff30e6c8d2e69e4523c83e7fc18af67df84b6b4  cgqrrrdqh/tex1.bmp (加密ZIP容器, 同v1)
f861cbedbb14456acaeb70097dacbc0a8c1f3d0cf7b960dc54cf9d4af7b93801  cgqrrrdqh/d.bmp (隐写载荷, 同v1)
2aba892b06ad4842159100e593f40ec78e0e1adf0b03884e61f8c7bcf5737b8a  cgqrrrdqh/EEVb5PEokh (加密载荷)
8536f4c05056ba4b32be73650c261a99366342c577415a11d069b33bb5c2d604  cgqrrrdqh/L5u5s9ps5V (加密载荷)
8dd621530fdceb76f4a72fff00094b907701fc9192526f527b4ce75396272dd2  cgqrrrdqh/YAHkLRPrNo (加密载荷)
0e48ddd3684fc8fdca7af66fc539140d800f963748aa2fe5fc8bd7513923f739  cgqrrrdqh/ctDLTlAjbr (加密载荷)
fc40ff4109cade3134c2990cdc7c64fa5344e0a77fb9bb88b9ef826caac9db7a  cgqrrrdqh/f7M4GWH8BL (加密载荷)
dad09779024f0a958acc8ee47d55aeb4143006c583fe40fbe1725aee5d661100  cgqrrrdqh/j12HgxFGIG (加密载荷)
2e7a28ca76ff794d7a7cade07fb0ab7645fdce3dd89582eb46562585d1da9e8e  cgqrrrdqh/nIMnWTa4iI (加密载荷)
e757034bd27918b37908f29fcd8005f730019a1cb088ca0a6907fff6b8db36dd  cgqrrrdqh/xidytuWCRP (加密载荷)
```

---

## 三、分发基础设施情报（本次实测）

### 3.1 确认活跃的 PoW 分发站点（同 `fx-quickq` 下载机制）
使用完全相同的 `/api_get_task.php` + `/api_verify.php`（SHA-256 PoW, difficulty=4）→ 阿里云 OSS 签名链接：
```
down.fx-quickq.com.cn   （主样本来源，已抓取）
down.quickqvpn.com
kuailian.io
letevpn.world
```

### 3.2 确认活跃的直连分发站点（不同 CDN 后端）
```
bestquickq.com / quickqvpn.net → dl.awsdl.com / www.awsdl.com  (quickq_win.exe, quickq_android.apk)
fastquickq.com                 → cdn.awsdl.xyz                  (heibao_win.exe/黑豹, heibao_android.apk)
quick-q.com                    → s3.daliaohengsheng.com         (yunyin_v1.7.x/云隐, 及木马化 ClashVerge .dmg)
```

### 3.3 解析中的仿冒域名（共 59 个，SEO 投毒/AI 生成站点候选）
覆盖 `quickq* / kuailian* / letsvpn* / quick-q*` 在 `.com/.com.cn/.cn/.net/.vip/.xyz/.top/.app/.io/.world` 上的大量排列组合，多数托管于 Cloudflare（`104.21.*`、`172.67.*`）与阿里云。完整清单见 `distribution_sites.json`。

### 3.4 关键载荷分发 URL（供防火墙/URL 过滤封禁）
```
https://dl.awsdl.com/download/3rdparty/seo/quickq/quickq_win.exe
https://dl.awsdl.com/download/3rdparty/seo/quickq/quickq_android.apk
https://www.awsdl.com/download/3rdparty/seo/quickq/quickq_win.exe
https://cdn.awsdl.xyz/3rdparty/seo/heibao/heibao_win.exe
https://cdn.awsdl.xyz/3rdparty/seo/heibao/heibao_android.apk
https://s3.daliaohengsheng.com/yunyin_v1.7.6.exe
https://s3.daliaohengsheng.com/yunyin_v1.7.3.apk
https://s3.daliaohengsheng.com/ClashVergeYY175.dmg
<OSS>.oss-accelerate.aliyuncs.com/*.zip   （bucket 轮换: qoxkjdi→fvjifek→…, AccessKey LTAI5tDVr1AeszcfPizjSxiP）
```

---

## 四、变体家族归类（初步）

| 品牌 | 打包器 | 客户端技术 | 与 Falcon 家族关系 |
|------|--------|-----------|-------------------|
| QuickQ / 快连（fx-quickq，下一代） | Inno 5.3.9 | .NET/Go LetsVPN + Falcon SDK | **核心家族**（douyinray P2CDN） |
| QuickQ（awsdl 渠道） | Inno 6.1.0 | 待沙箱确认 | 疑同源（新 Inno 版本线） |
| 黑豹 / Heibao | Inno 6.1.0 | **Flutter + tap0901 (OpenVPN TAP)** | 架构不同，疑独立/协同渠道 |
| 云隐 / Yunyin | NSIS 3.11 | 待沙箱确认 | 待确认 |

> **说明：** 黑豹为 Flutter 架构 + tap0901 驱动，与 QuickQ/LetsVPN 的 Falcon/libwin 技术栈不同，可能是同一分发团伙（awsdl.com/awsdl.xyz 共用后端）投放的另一 VPN 品牌。建议团队在沙箱内对每个变体做完整动态分析。

---

## 五、建议的团队后续动作
1. 在隔离沙箱解压（密码 `infected`）并对每个变体做完整动态分析。
2. 将 §1/§2 全部 SHA256 入病毒库（参考 `virus_sample_library_guide.md`）。
3. 将 §3 全部域名/URL 加入企业防火墙与 URL 过滤黑名单。
4. 针对下一代新增的 `douyinray7.exe` 抖音宿主与输入钩子模块补充检测规则。
5. 对 `awsdl.com` / `awsdl.xyz` / `daliaohengsheng.com` 后端做持续监控（多品牌共用）。
