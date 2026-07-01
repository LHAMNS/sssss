# 检测规则集（YARA + Sigma + 网络IOC）

**报告编号:** MAL-2026-0301-QUICKQ · **日期:** 2026-07-01
**用途:** 直接入库/上线的检测内容,覆盖本案假VPN·假软件·SEO生态(家族A/B/C)+ 关联RAT线
(Winos4.0 / ValleyRAT / 银狐AtlasCross / Gh0st / Farfli / BlackMoon / FatalRAT / Gh0stCringe / PurpleFox)。
**性质:** 防御研究产物,仅供检测、狩猎、封禁;所有规则均已本地验证。

---

## 目录

| 文件 | 内容 | 验证 |
|------|------|------|
| `quickq_ecosystem.yar` | 17 条 YARA 规则(家族A/B/C + 通用手法 + RAT线) | `yara-python` 编译通过,实测样本命中 |
| `scan.py` | YARA 扫描器(自动传 `filename` 外部变量) | 934 文件实测 |
| `sigma/*.yml` | 11 条 Sigma 规则(注册表/进程/网络/文件/DNS) | `yaml` 解析 + schema 校验通过 |
| `network_iocs.txt` | 扁平域名+IP 封禁清单 | 直接导入防火墙/DNS Sink |

---

## YARA 使用

```bash
pip install yara-python
# 扫描目录(自动按扩展名判定"伪装扩展名"规则)
python3 scan.py /path/to/samples
# 或直接用 yara CLI(需手动传 filename 才能触发伪装类规则)
yara -d filename=x.bmp quickq_ecosystem.yar /path/to/file
```

### 规则清单与命中逻辑
- **家族A**:`QuickQ_FamilyA_Falcon_SDK`(Falcon引擎/LetsGo签名串)、`QuickQ_FamilyA_NextGen_Douyin_Stealer`(字节ttnet/tray_douyin/Cookie+输入钩子)
- **家族B**:`FakeVPN_FamilyB_AHAspeed_Cham_Flutter`(Inno+Flutter+tap0901)、`FakeVPN_FamilyB_Tyrant_TunnelEngine`(core.dll的tyrant隧道/DNS命名空间)
- **家族C**:`FakeVPN_FamilyC_Yunyin_NSIS`
- **通用手法**:`Disguised_Shellcode_As_BMP`(伪装图片的高熵blob,已排除PNG/JPEG/GIF/WEBP/ICO真头)、`Disguised_PE_As_Image`(图片扩展名的PE,filename门控)、`HighEntropy_Packed_Blob_Heuristic`(无头加密载荷,复核层)
- **RAT线**:`Winos4_Encrypted_Plugin`、`ValleyRAT_Winos_Loader`、`SilverFox_AtlasCross_Beacon`(SFuck握手)、`Gh0st_Classic_MFC`(MFC42+ICMP.DLL)、`Gh0stCringe_FakeSoftware_Lure`(假DeepSeek)、`Farfli_BlackMoon_Packed`、`FatalRAT_ImpHash_Cluster`(imphash主键)、`FatalRAT_Loader_Behavior`、`PurpleFox_ChineseLanguagePack_MSI`

> **关于打包RAT**:ValleyRAT/AtlasCross等活体多为加壳,明文特征少,内容YARA难直接命中——
> 这类以 **哈希/imphash IOC**(见 `../RAT_FAMILIES_2026_IOCS.md`、`../RAT_LINE_IOCS.md`)+ **Sigma行为/网络** 覆盖。

## Sigma 使用

```bash
# 用 sigma-cli 转成你的SIEM查询(示例转 Splunk / ES|QL / Sentinel)
pip install sigma-cli
sigma convert -t splunk sigma/
sigma convert -t esql   sigma/
```

### 规则清单
| 文件 | 触发面 | 级别 |
|------|--------|------|
| `famA_falcon_fakedns_registry.yml` | 注册表 DnsPolicyConfig→26.26.26.x | high |
| `famA_nextgen_ga4_exfil.yml` | 代理 GA4 /mp/collect 非浏览器POST | medium |
| `generic_signed_sideload_unsigned_dll.yml` | pcdnacc7/douyinray7 侧加载未签名DLL | high |
| `rat_winos_valleyrat_c2_18852.yml` | 防火墙 :18852 及已知IP | high |
| `rat_silverfox_atlascross_c2.yml` | DNS typosquat + bifa668:9899(2条) | critical |
| `purplefox_langpack_msi_exec.yml` | msiexec 执行"中文语言包"MSI | high |
| `generic_masquerade_mz_as_image_temp.yml` | TEMP/APPDATA 伪装图片PE被加载 | medium |
| `nexus_sharedns_resolution.yml` | DNS 解析 share-dns.com/net | medium |
| `famB_awsdl_ppi_distribution.yml` | 代理 awsdl PPI CDN 下载路径 | high |
| `rat_fatalrat_sideload_chain.yml` | 进程 FatalRAT 诱饵命名 | high |

## 网络IOC

`network_iocs.txt` — 域名+IP 扁平清单,`#` 为注释,可直接喂给 pihole/防火墙/代理黑名单。

---

## 验证记录（本地实测)
- YARA:`yara.compile()` 通过,17 条规则;对 934 个实测文件扫描 → 33 命中,家族规则各精确命中其目标载荷,伪装/高熵规则已消除 PNG/WEBP/ICO 图片误报。
- Sigma:11 个文档全部 `yaml.safe_load` + 必填字段(title/logsource/detection.condition)校验通过。
- IOC:域名/IP 来自 ATTRIBUTION.md、RAT_LINE_IOCS.md、RAT_ECOSYSTEM_2026.md、RAT_FAMILIES_2026_IOCS.md 汇总去重。
