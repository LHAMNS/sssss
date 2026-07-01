/*
============================================================================
 QuickQ / 假VPN·假软件·SEO 生态 + 关联 RAT 线  YARA 检测规则集
 报告编号 : MAL-2026-0301-QUICKQ
 日期     : 2026-07-01
 依据     : 本案实测样本(Family A/B/C + RAT线)+ abuse.ch IOC + 公开厂商报告
 覆盖     : Family A(快连/QuickQ Falcon+次世代 douyinray) / Family B(AHAspeed·Cham Flutter)
            / Family C(云隐 NSIS) / Winos4.0 / 银狐 AtlasCross / ValleyRAT / Gh0st(经典)
            / Farfli / BlackMoon / FatalRAT / Gh0stCringe / PurpleFox
 说明     : 需要 pe 模块支持 imphash 规则(yara -x 或默认已含)。
 免责     : 规则来自防御研究,仅用于检测/狩猎/入库,禁止用于攻击。
============================================================================
*/

import "pe"
import "math"

/*
 外部变量 filename:扫描器需通过 -d filename=<名> 传入(本目录 scan.py 会自动传)。
 未传入时默认为空字符串,"伪装扩展名"两条规则不会误报。
*/

/* ---------------- Family A : 快连 / QuickQ ---------------- */

rule QuickQ_FamilyA_Falcon_SDK
{
    meta:
        desc   = "家族A 快连/QuickQ Falcon SDK 引擎(DNS劫持/流量拦截/自研TUN栈)"
        family = "FamilyA-Falcon"
        ref    = "MAL-2026-0301"
        author = "IR-team"
    strings:
        $a = "falcon.ipaddr-decrypt" ascii
        $b = "falcon.log-encrypt" ascii
        $c = "bitbucket.org/letsgo-network" ascii
        $d = "fakeDns" ascii
        $e = "DNSDispatcher" ascii
        $f = "LetsGo Network Incorporated" ascii
        $g = "devel@letsgo-network.com" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule QuickQ_FamilyA_NextGen_Douyin_Stealer
{
    meta:
        desc   = "家族A 次世代载荷 douyinray7:字节ttnet + tray_douyin + Cookie/账号窃取 + 全局输入钩子"
        family = "FamilyA-NextGen"
        ref    = "MAL-2026-0301 (2026-05 build)"
    strings:
        $t1 = "bytedance\\ttnet_wrapper" ascii
        $t2 = "cronet_engine_wrapper.cc" ascii
        $p1 = "project\\tray_douyin" ascii
        $p2 = "cookie_manager\\cookie_manager.cc" ascii
        $p3 = "account_manager.cc" ascii
        $p4 = "global_input_hook_manager.cc" ascii
        $p5 = "app_launch_detector.cc" ascii
        $c1 = "overwrite cookie db finished" ascii
        $c2 = "insert or update cookie" ascii
        $n  = "douyinray" ascii nocase
    condition:
        uint16(0) == 0x5a4d and
        ( (1 of ($t*) and $p1) or (3 of ($p*)) or ($n and 2 of ($c*)) )
}

/* ---------------- Family B : AHAspeed / Cham (Flutter 换皮) ---------------- */

rule FakeVPN_FamilyB_AHAspeed_Cham_Flutter
{
    meta:
        desc   = "家族B AHAspeed/Cham Flutter 假VPN量产换皮(Inno + Flutter + tap0901)"
        family = "FamilyB-Flutter"
        ref    = "MAL-2026-0301"
    strings:
        $inno = "Inno Setup" ascii
        $flu  = "flutter_windows.dll" ascii
        $tap  = "tap0901" ascii nocase
        $a    = "AHAspeedWebsiteIcon" ascii
        $c    = "ChamWebsiteIcon" ascii
        $h1   = "ahaspeed.com" ascii nocase
        $h2   = "hellocham.com" ascii nocase
    condition:
        uint16(0) == 0x5a4d and $flu and ($tap and ($a or $c or $h1 or $h2 or $inno))
}

rule FakeVPN_FamilyB_Tyrant_TunnelEngine
{
    meta:
        desc   = "家族B 核心网络引擎 core.dll(tyrant 命名空间:tunnel/dns_cache/http_proxy/nic_mgr)"
        family = "FamilyB-core"
        ref    = "MAL-2026-0301 实测 core.dll"
    strings:
        $n1 = "tunnel@net@async@tyrant" ascii
        $n2 = "_dns_cache@net@async@tyrant" ascii
        $n3 = "http_proxy@net@async@tyrant" ascii
        $n4 = "nic_mgr@tunnel@net@async@tyrant" ascii
    condition:
        2 of them
}

/* ---------------- Family C : 云隐 (yunyin NSIS) ---------------- */

rule FakeVPN_FamilyC_Yunyin_NSIS
{
    meta:
        desc   = "家族C 云隐 NSIS 加载器(daliaohengsheng/hideyun 后端)"
        family = "FamilyC-yunyin"
        ref    = "MAL-2026-0301"
    strings:
        $nsis = "Nullsoft" ascii
        $h1   = "daliaohengsheng.com" ascii nocase
        $h2   = "hideyun.com" ascii nocase
        $h3   = "quick-q.com" ascii nocase
        $y    = "yunyin" ascii nocase
    condition:
        uint16(0) == 0x5a4d and ($nsis and (1 of ($h*) or $y))
}

/* ---------------- 通用手法：伪装 / 侧加载 ---------------- */

rule Disguised_Shellcode_As_BMP
{
    meta:
        desc = "伪装成图片(.bmp/.png/.jpg)的高熵 shellcode/加密ZIP(本案 hfel/t7/tex1/d.bmp)"
        ref  = "MAL-2026-0301"
    condition:
        (filename matches /\.(bmp|png|jpg|jpeg|gif|ico|dat)$/i) and
        // 排除真实图片/容器魔数(WEBP等以RIFF开头的合法图片不误报)
        uint16(0) != 0x4d42 and   // BM
        uint16(0) != 0x5089 and   // PNG
        uint16(0) != 0xd8ff and   // JPEG
        uint16(0) != 0x4947 and   // GIF
        uint16(0) != 0x4952 and   // RIFF (WEBP/WAV)
        uint16(0) != 0x4b50 and   // ZIP
        uint32(0) != 0x00010000 and  // ICO (含内嵌PNG的合法图标,熵高但非恶意)
        filesize > 100KB and filesize < 8MB and
        math.entropy(0, filesize) > 7.2
}

rule Disguised_PE_As_Image
{
    meta:
        desc = "扩展名伪装成图片但实为 PE(MZ 头) —— BlackMoon/多家RAT投递常用"
        ref  = "MAL-2026-0301"
    condition:
        (filename matches /\.(jpg|jpeg|png|gif|bmp|ico|txt|log|dat)$/i) and
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3C)) == 0x00004550
}

rule HighEntropy_Packed_Blob_Heuristic
{
    meta:
        desc = "通用启发:无已知文件头的高熵加密载荷(RAT打包器/加密插件;需人工复核)"
        ref  = "MAL-2026-0301 (heuristic)"
    condition:
        filesize > 200KB and filesize < 8MB and
        math.entropy(0, filesize) > 7.6 and
        // 排除已知媒体/容器/可执行魔数,只留"无头加密blob"
        uint16(0) != 0x5089 and   // PNG
        uint16(0) != 0xd8ff and   // JPEG
        uint16(0) != 0x4947 and   // GIF
        uint16(0) != 0x4d42 and   // BMP
        uint16(0) != 0x4952 and   // RIFF/WEBP
        uint16(0) != 0x4b50 and   // ZIP
        uint16(0) != 0x8b1f and   // gzip
        uint16(0) != 0x5025 and   // PDF
        uint16(0) != 0x6152 and   // RAR
        uint16(0) != 0x7a37 and   // 7z
        uint16(0) != 0x5a4d and   // MZ (PE 另有专门规则)
        uint32(0) != 0x00010000   // ICO
}

/* ---------------- Winos 4.0 / ValleyRAT (Gh0st 衍生) ---------------- */

rule Winos4_Encrypted_Plugin
{
    meta:
        desc = "Winos4.0 加密插件(非MZ,运行时解密加载;本案实测 /NEW/plugin1-3.dll)"
        ref  = "MAL-2026-0301 实测 + Rapid7"
    strings:
        $s1 = "/NEW/plugin" ascii
        $s2 = "/m2/plugin" ascii
        $s3 = "plugin1.dll" ascii nocase
    condition:
        // (a) 加载器/配置/内存中引用插件下载路径
        (any of ($s*))
        or
        // (b) .dll 扩展但非 PE + 高熵 = 加密插件体(本案 19 d7 0e 87…)
        ( (filename matches /\.dll$/i) and uint16(0) != 0x5a4d and
          filesize > 200KB and filesize < 40MB and math.entropy(0, filesize) > 7.5 )
}

rule ValleyRAT_Winos_Loader
{
    meta:
        desc = "ValleyRAT / Winos4.0 加载器(Gh0st 衍生;C2 :18852 家族)"
        ref  = "MAL-2026-0301 + Nextron/Rapid7"
    strings:
        $c2a = ":18852" ascii
        $a1  = "winos" ascii nocase
        $a2  = "ValleyRAT" ascii nocase
        $a3  = "insttect.exe" ascii nocase
        $a4  = "intel.dll" ascii nocase
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

/* ---------------- 银狐 Silver Fox / AtlasCross ---------------- */

rule SilverFox_AtlasCross_Beacon
{
    meta:
        desc = "银狐 AtlasCross/Atlas RAT 握手('SFuck')与 C2 bifa668"
        ref  = "Hexastrike / The Hacker News 2026-03"
    strings:
        $sfuck = { 53 46 75 63 6b 00 00 00 }   // "SFuck" 握手
        $c2    = "bifa668.com" ascii
        $c3    = "quickq-quickq.com" ascii
    condition:
        any of them
}

/* ---------------- Gh0st 经典 & 变种 ---------------- */

rule Gh0st_Classic_MFC
{
    meta:
        desc = "经典 Gh0st RAT(MFC42 + 'Error loading ICMP.DLL';本案 wangkelong 实测)"
        ref  = "MAL-2026-0301 实测 + Unit42"
    strings:
        $mfc  = "MFC42.DLL" ascii nocase
        $icmp = "Error loading ICMP.DLL" ascii
        $g1   = "Gh0st" ascii
    condition:
        uint16(0) == 0x5a4d and (($mfc and $icmp) or ($g1 and $mfc))
}

rule Gh0stCringe_FakeSoftware_Lure
{
    meta:
        desc = "Gh0stCringe(=CirenegRAT)经假DeepSeek等软件投递(deepseek.msi)"
        ref  = "MAL-2026-0301 abuse.ch + Unit42"
    strings:
        $l1 = "deepseek" ascii nocase
        $l2 = "Ghst.exe" ascii nocase
        $m  = "MFC42" ascii
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0xE011CFD0 /*MSI/OLE*/) and any of them
}

/* ---------------- Farfli / BlackMoon ---------------- */

rule Farfli_BlackMoon_Packed
{
    meta:
        desc = "Farfli / BlackMoon 打包体(高熵 + 伪装图片扩展投递,本案实测家族)"
        ref  = "MAL-2026-0301 实测"
    strings:
        $bm = "BlackMoon" ascii nocase
        $ff = "Farfli" ascii nocase
    condition:
        uint16(0) == 0x5a4d and
        ( any of them or (math.entropy(0, filesize) > 7.3 and filesize < 4MB) )
}

/* ---------------- FatalRAT (imphash 聚类 + 诱饵) ---------------- */

rule FatalRAT_ImpHash_Cluster
{
    meta:
        desc = "FatalRAT 同工具链聚类(abuse.ch imphash 主键;近年假软件/中文SEO投递)"
        ref  = "MAL-2026-0301 abuse.ch get_taginfo"
    condition:
        pe.is_pe and
        (
            pe.imphash() == "9b201090749bae06a761156dbad9c4f1" or
            pe.imphash() == "3a8897c84eb41f36b4bbabcc617408b8" or
            pe.imphash() == "6c306e45fa9f977a2f45c8a08df084d5" or
            pe.imphash() == "79346d73f8d60fa11ceef27932261e6a"
        )
}

rule FatalRAT_Loader_Behavior
{
    meta:
        desc = "FatalRAT 多阶段加载(DLL侧加载→核;诱饵含中文/假软件名)"
        ref  = "MAL-2026-0301"
    strings:
        $a1 = "FatalRAT" ascii nocase
        $l1 = "转接口" ascii wide
        $l2 = "音频调试" ascii wide
        $l3 = "Chromele" ascii nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}

/* ---------------- PurpleFox (中文语言包 MSI 诱饵) ---------------- */

rule PurpleFox_ChineseLanguagePack_MSI
{
    meta:
        desc = "PurpleFox 中文语言包诱饵 MSI(点击安装中文语言包*.msi;近期专打中文用户)"
        ref  = "MAL-2026-0301 abuse.ch get_taginfo"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }        // OLE/MSI 复合文档头
        $l1  = "语言包" ascii wide
        $l2  = "点击安装" ascii wide
        $l3  = "中文语" ascii wide
        $pf  = "PurpleFox" ascii nocase
    condition:
        ($ole at 0 and 1 of ($l*)) or $pf
}
