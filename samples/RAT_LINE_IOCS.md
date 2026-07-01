# RAT 线关联家族 IOC 清单（真正的"其他类型"·待团队用 Auth-Key 拉取）

**结论:** 本 PPI/SEO 生态之外，真正不同的"其他类型"是 **RAT 线**（Silver Fox / Void Arachne / AtlasCross / ValleyRAT / Winos 4.0 / Gh0st / Farfli）。这些**无法在本环境匿名下载**（MalwareBazaar & ThreatFox 现已强制 Auth-Key），故此处提供**可直接入库的哈希清单 + 拉取方法**。

**关键关联:** `quickq-quickq.com` 是已确认的 **Silver Fox → Atlas RAT 投递域名** —— 直接把本 QuickQ 活动与 RAT 线绑定。ValleyRAT ≈ Winos 4.0（均 Gh0st RAT 衍生）；Silver Fox = SwimSnake = UTG-Q-1000 = Void Arachne = Valley Thief。

## 拉取方法（团队执行）
```bash
# 1. 免费注册 https://auth.abuse.ch/ 获取 Auth-Key
# 2. 按标签查 / 按哈希下（样本包密码同为 infected）
curl -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: <KEY>" -d 'query=get_taginfo&tag=ValleyRAT&limit=50'
curl -X POST https://mb-api.abuse.ch/api/v1/ -H "Auth-Key: <KEY>" -d 'query=get_file&sha256_hash=<HASH>' -o s.zip   # unzip -P infected
```

## 待拉取样本哈希（SHA256）
| # | SHA256 | 家族/阶段 | 文件名 | 来源 |
|---|--------|----------|--------|------|
| 1 | 1e57ac6ad9a20cfab1fe8edd03107e7b63ab45ca555ba6ce68f143568884b003 | Winos 4.0 (LetsVPN NSIS) | Lets.15.0.exe | Rapid7 |
| 2 | 4fdedadaa57412e242dc205fabdca028f6402962d3a8af427a01dd38b40d4512 | Winos 4.0 loader (Catena) | insttect.exe | Rapid7 |
| 3 | b8e8a13859ed42e6e708346c555a094fdc3fbd69c3c1cb9efb43c08c86fe32d0 | Winos 4.0 stage-2 | intel.dll | Rapid7 |
| 4 | 8009908c6c76a72e20e4020a9f9eb9e4d4203507f67a624ecf7f4ed672cf4b68 | AtlasCross/Atlas RAT | MainDll.dll | Hexastrike |
| 5 | fa5d3a9eebf9310148e7b980fefa7bc3f3a8e8ee7a8d0bd21a057c54c5a47560 | Atlas RAT payload | — | Hexastrike |
| 6 | 42da0ad45bfe9b7f82247d780a32e128e0b00846fe76eea96250e3088f54909b | Atlas RAT (2025-11) | — | Hexastrike |
| 7 | d67545f666e89419c0ccd0346929b1906b46eb8b3cff2b94671c6d5755e81f3e | Atlas RAT (2025-11) | — | Hexastrike |
| 8 | e3f04545fb59d2943a4a30cd1b6fa39cb36e1e803301ab2ca5fad2bca84f04dd | Silver Fox 投递档(quickq/VPN) | — | Hexastrike |
| 9 | 5841ad433ab199bb784a4d33fd629101d22de6e44dce0606c08b92f8b4709380 | Silver Fox Setup Factory | — | Hexastrike |
| 10 | 9ede6da5986d8c0df3367c395b0b3924ffb12206939f33b01610c1ae955630d1 | ValleyRAT (假Telegram) | tg.exe | Nextron |
| 11 | c37d0c9c9da830e6173b71a3bcc5203fbb66241ccd7d704b3a1d809cadd551b2 | Gh0st (假DeepSeek) | deepseek_release_X64.exe | Unit42 |
| 12 | 299e6791e4eb85617c4fab7f27ac53fb70cd038671f011007831b558c318b369 | Gh0st payload | svchos1.exe | Unit42 |
| 13 | 1395627eca4ca8229c3e7da0a48a36d130ce6b016bb6da750b3d992888b20ab8 | Gh0st payload | svchos1.exe | Unit42 |
| 14 | da2c58308e860e57df4c46465fd1cfc68d41e8699b4871e9a9be3c434283d50b | RONINGLOADER (DragonBreath→gh0st) | klklznuah.msi | Elastic |
| 15 | 3dd470e85fe77cd847ca59d1d08ec8ccebe9bd73fd2cf074c29d87ca2fd24e33 | gh0st/Farfli-class 终载 | 6uf9i.exe | Elastic |
| 16 | 2515b546125d20013237aeadec5873e6438ada611347035358059a77a32c54f5 | RONINGLOADER BYOVD 驱动 | ollama.sys | Elastic |
| 17 | 491872a50b8db56d6a5ef1ccabe8702fb7763da4fd3b474d20ae0c98969acfe5 | Gh0st (Campaign Chorus) | win64wsotusapdeuw.msi | Unit42 |
| 18 | 495ea08268fd9cf52643a986b7b035415660eb411d8484e2c3b54e2c4e466a58 | Gh0st (假i4Tools) | i4Tools8_v8.33_Setup_x64.msi | Unit42 |

## 关联网络 IOC（加入封禁/检测）
- **Silver Fox/Atlas 投递域名:** quickq-quickq.com, app-zoom.com, signal-signal.com, telegrtam.com.cn, trezor-trezor.com, ultraviewer-cn.com, wwtalk-app.com, www-surfshark.com, www-teams.com, kefubao-pc.com, eyy-eyy.com
- **Atlas C2:** bifa668.com, 61.111.250.139:9899 · NS a.share-dns.com/b.share-dns.net · beacon `53 46 75 63 6b 00 00 00`("SFuck")
- **Winos4.0/LetsVPN C2(:18852):** 156.251.17.243, 134.122.204.11, 27.124.40.155, 43.226.125.44, 47.238.125.85, 137.220.229.34, 8.210.165.181, 143.92.61.154, 47.86.28.28, 143.92.63.144, 112.213.116.91 · (:443) 103.46.185.44, 202.79.168.211, 27.122.59.71, 202.79.171.133
- **Gh0st 假冒(Unit42):** xiaobaituziha.com, xiazailianjieoss.com, xiaofeige.icu, 1235saddfs.icu, yqmqhjgn.com, djbzdhygj.com · IP 156.251.25.112/43, 154.82.84.227, 95.173.197.195, 103.181.134.138
- **RONINGLOADER C2:** qaqkongtiao.com

## 来源
Rapid7 (Winos4.0/LetsVPN) · Hexastrike (Silver Fox/Atlas RAT) · The Hacker News 2026-03 (AtlasCross) · Nextron (ValleyRAT) · Unit42 (Gh0st 假冒) · Elastic (RONINGLOADER) · abuse.ch (需 Auth-Key)
