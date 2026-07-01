# RAT 家族扩展 IOC（abuse.ch / MalwareBazaar 认证通道拉取）

**报告编号:** MAL-2026-0301-QUICKQ（RAT线IOC扩充）· **日期:** 2026-07-01
**来源:** MalwareBazaar `get_taginfo`(认证通道,Auth-Key)· **范围:** 与本案 RAT 生态关联的中国背景家族,IOC元数据入库(哈希/imphash/文件名诱饵/类型),非无差别活体囤积。

**为何选这三个家族:** 均为**中文用户定向 + 假软件/SEO投递**打法,与本案(QuickQ假VPN + Silver Fox冒牌投递)受害者画像和TTP高度重合。

---

## FatalRAT  (50 样本)

中国背景商用RAT;近年经假软件/中文SEO投递(冒充 Chrome/Telegram/WhatsApp/输入法),多阶段加载(DLL侧加载→FatalRAT核),与本案假软件SEO打法同源。

- **文件类型分布:** {'exe': 42, 'dll': 2, '7z': 1, 'msi': 3, 'rar': 2}
- **首见时间范围:** 2025-06-29 02:30:16 → 2026-04-08 00:50:16

**imphash 聚类（≥2 表示同构建/同工具链,可做狩猎主键):**

| imphash | 样本数 |
|---------|--------|
| `9b201090749bae06a761156dbad9c4f1` | 9 |
| `3a8897c84eb41f36b4bbabcc617408b8` | 6 |
| `6c306e45fa9f977a2f45c8a08df084d5` | 3 |
| `79346d73f8d60fa11ceef27932261e6a` | 3 |
| `5e5e0516b9cb49f396b0ce208c8bee82` | 2 |
| `37ff436608dfd4229b923028faaf734a` | 2 |

**诱饵文件名（社工线索,含中文语言包/假软件）:**
```
猪猪音频调试工具箱.exe
Chromele_13.02.11转接口.msi
Setup安装包.exe
```

**样本哈希 SHA256（前 25,家族标签 FatalRAT;样本包密码 `infected`）:**
```
e1b4c8df3cd7a51d8751b3c3c8b143b5feee7eb1e4c786b4ffecc370a60856ee
15582577479f182cc373f67436ca607fc39138762894adae4da0c2136aeac496
c796d4b14d6cd27b2bcf3db13677c824b0d7eb4a133567a4fe6e40b4e35b33a4
d477cac8cead223e8670770c6c0da5a441d7497d362db56c845a4f97c2905a9f
958634f5699c996ebe6ec331b5421580ae1eba5fbc55da387fdfee04ecc702bd
3f30eb517d144720c9ff76b22b67f24888963f550e4b2ee86a9db57a1979b245
390dd7156785ef7c2fc83135038f7bd492d32f72311c0a80280380ca7f79f11a
288299a40472f64a2c51cd75f9cd27692819c4927fdb65530f88124aef4b2d78
66f8447a4835720a737cc043f1cfd079e7668f9e038e4b991b13fbaab850f379
c258bc3b4e7828735830dfa3004facc7a6612eecc2ab5dfb2d16c7bda65b0a1f
7637a316f0b40eedb840ad41a3e56db7b9432b54c03508774d99747ec44a85f1
ba64716eb4f78e4c06358ca3b8a088c9ca452bd192356b31e13b2c8a19cae1a2
8d9d28835929c45ec67d20204c8bb2e1d16db52c04b909ebbcd25cb2df9051a7
243cd136b5aa42c20c048a1fccb215749c482519488f46b05130f5f7dc33583d
c5ee5a6276dbfe9ba3b955fca16f049baf43c4438a970295b33a52962bbae98f
a7b44fc9f85021736bc5f4fd076763690d334fd8284b9bb0c13efac5ae440235
00253f82c78aa90a213a1c3d7b828a66ba50b10b69cbd407e54061dc5830b684
2a331b359f85b9f2834b268d677b9286e9e4d71ff114ba56d3c55728e32096c6
013459242cd47dfb0d484ea5a5731e9f3f62dd0a9f625835a4e98ceb81b3caf9
e8e253972384db09a238058bb55f18a80a33e534dde1845f0f1c0d48fdf9453f
856991ba177f3a8a3d5209551d2074a198fcc6aa6f5b1e4280ed53b07271ffdd
b5c6264c058d9604b40cbc267d95be46db71f4069ca07a73686a74aeb64f0606
7a4cd1e7da686434306fa4f3a50b199fc120625bfd41dd39a69768e0fdbe91bb
5e1b7a390ea9570bf8ad1978585e0f5a2b975880c5acab66b89f3f3e40780294
125102e802e142750ba8e44542febf0466607b22b07cef60a0414a2e079a706a
```

---

## Gh0stCringe  (13 样本)

Gh0st RAT 变种(=CirenegRAT);本案已见其 lineage(假DeepSeek deepseek.msi 与报告 Unit42 线一致),键鼠记录/文件窃取。

- **文件类型分布:** {'msi': 1, 'exe': 9, 'dll': 3}
- **首见时间范围:** 2021-03-20 11:16:49 → 2025-06-23 01:27:25

**imphash 聚类（≥2 表示同构建/同工具链,可做狩猎主键):**

| imphash | 样本数 |
|---------|--------|
| `d9c7208ff3022bb34870c7ddeb406eb1` | 5 |
| `f6e227b328b6aba3a7655dd732629303` | 3 |

**诱饵文件名（社工线索,含中文语言包/假软件）:**
```
deepseek.msi
海外模式前期准备工具.exe
账款明细3.20_xlsx.exe
```

**样本哈希 SHA256（前 25,家族标签 Gh0stCringe;样本包密码 `infected`）:**
```
8be316e9308a263fb890d2847d46b9db59a42e76997dfbc7c7c91a46b0520fc9
2e8018f36f3e682f8c8f407448cb2c41e639707c251ae5877090d61286143ba4
a8814d551510e0aa051fa2022ea305e55143f2482d5e1532126d542fec1589e9
0ab3f28c2e63c11de5149502fb3d04411d07d00a46ab90b7fdecbc0daf3190e4
d0eac987bcbfdc5c85ec8190be7366798cf06035ffaf4088a41f3b82c1ab498c
9d036fa361566113d0a9df117d17d45376d04d5c94d7ec82325701bcebbb24f9
8ade56bd356d12804d384ca24fe876346498a25870f6caf08e16d0c73e5abe59
18158134da1bb476cc580a19d2e61e1cc378452ad527022169040344abcb22a3
4853453ba12dde157cec10692eb874f34f333a6ccfb0782bf36ba2c3a57713dc
e7c3f20e293112d02c667e098467572371107a5316ffdf4434dea2e490434771
acaed16a37962b29231a2b0842b616000656a12ff66ce41830ca855a207fc5dc
c973c31f8af3d15abb5963e2764f534e5263828320e9c15e57c953392c32ce65
c9ef2a3ae38154b1dacc2724d2b0e097e893c7617602969fcf3f56abe5d96d72
```

---

## PurpleFox  (50 样本)

PurpleFox rootkit/僵尸网络(MSI投递+BYOVD驱动隐藏);近期大量**中文语言包**诱饵MSI(点击安装中文语言包*.msi)专打中文用户,与本案受害者画像重合。

- **文件类型分布:** {'msi': 25, 'exe': 15, 'zip': 7, 'dll': 2, 'doc': 1}
- **首见时间范围:** 2023-11-02 15:18:44 → 2026-05-28 00:16:17

**imphash 聚类（≥2 表示同构建/同工具链,可做狩猎主键):**

| imphash | 样本数 |
|---------|--------|
| `19d4e66d725c89ba6712b82bebc8196d` | 2 |

**诱饵文件名（社工线索,含中文语言包/假软件）:**
```
点击安装中文语言包a.msi
点击安装简体中语言包l.msi
win32-chromesog.msi
openclaw installation.exe
谷歌安装包.msi
ChromeSetup-6808.msi
ChromeSetup_D.msi
ChromeSetup.msi
剧情.msi
007 切入投资.msi
ChromeSetup-7000.msi
telegram.msi
ChromeSetup-6581.msi
SZIOFDNNCJ_WdcweEoetr_Setup_ChromeSetup.msi
deepseek.msi
和平模拟测绘.exe
k40p一键刷入TWRP-A14.exe
打包安装包 (2).zip
Chrome-Setup.msi
```

**样本哈希 SHA256（前 25,家族标签 PurpleFox;样本包密码 `infected`）:**
```
1cfb6fc65a1c6b9f28c76cfc300a3b6e9afcf98d5793e306d44eb6c18ba9a63c
ee39f1387ecff828c7f30afd01eae3bca27727f804a4167e91a9c841d1790cb2
524f4410012eaf96e6a64aaf4d5b014fa156f4ea31a5b1a6d6c99952d0eb63f8
138a06e4181d214861ac8815473c946ffd9e39fd56ac08fa9e3e122a8b377744
36fcbb6705cfb33700f750b218cf948f73590504a9fc31b4c1d9d8b517e5b8d9
4271e63615907efe119d10f3cf3fdc0e8571ff7e42e7be6f0ffe6fe9333ae6b1
6f0639714b080ffd89d082c080e2715e198536dc63ffda5aeadcf72406d31ffc
9690b2647b369a7924f6cff948e4693cb4ae297d2e02da16dd96a99e49d011d4
a6d7ebb2b18f9a77e4fdb78e3e29558a6b5605b4eb4e364ce9e120086a82ea32
0d907606ee58fb853289da236e9b9eb2d8797cc9eec312ac50267b38528d650b
8b2ada0760c4f139ca2043c750627ab9aed1e5ee09eaf87e54811f89f1cea567
bfafd06973daa3a0f0b6f08a9d0e6c2cc0f4eae098e97d177432aecf986e0002
dd615f60bc6c364b15ffdf93880e3dcdef9e7a2eb5444cd913c6e3a58b0943d5
4fa17fd83659ae7e3a015067326831963ddc5f1b194c76f14a22187febcb72a5
42faf503afd58bc7aa37f5d4340be11895cae9d29da75bfaa97180671172304c
1fe21e70078942fa8dc7bccb5362e86b0e6340c533eb8e01b59e34a0dd61bd05
49f8f5965f741105206c6616579c66bf84e63d9251c09e01b081e60e3771c50d
00c1314504b05c7fc7cc7280405f31165b9722c704520afef26aa88ff566b871
7a4bd378812093cf8aa2a3add92477ab4a0647b9e7c3d098560c982cfd971564
4c51e0b59abdf345fb17eea734f1d73203f633aba138b26d31bf975e38bb66ff
b877afc42d3fddf81f561aac9b68b7caf808290131c9fa3e4243b394455cde14
a5be16eea82ff1772f6949a2c018b21af85e9d3d303eb5f0fb472fbbf1fb2113
58a06239b83f94fabd06b499fcf466c9d3b099fe1f2f0a70847b13f9ab15aa4b
8be316e9308a263fb890d2847d46b9db59a42e76997dfbc7c7c91a46b0520fc9
1a7fefa02913c1054e4f0e82c9de74e2fb526bd4a589e861fb4f7f57b31ef9c8
```

---

## 拉取/复现方法（团队执行）
```bash
KEY=<abuse.ch Auth-Key>   # https://auth.abuse.ch/ 免费注册
# 按家族标签取 IOC 元数据
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: $KEY" -d 'query=get_taginfo&tag=FatalRAT&limit=50'
# 按哈希下活体(隔离沙箱内,zip 密码 infected)
curl -s -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: $KEY" -d 'query=get_file&sha256_hash=<HASH>' -o s.zip
```

> 入库建议: imphash 聚类做同工具链狩猎主键; PurpleFox 的"中文语言包"MSI诱饵名 + Gh0stCringe 的假DeepSeek 可直接进 URL/文件名检测。原始 JSON 见 `intel/abusech_iocs_2026.json`。
