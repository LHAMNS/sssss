#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一样本中和工作流 (MAL-2026-0301-QUICKQ)
=================================================
目的: 把仓库里所有样本统一处理成"只能分析、不能运行、不能被方便地拿去造马"的形式。

产出两层:
  1) 内部完整层  <label>_SECURE.zip   : AES-256 加密 + 破坏文件头的完整样本;
                                        密码为强随机、不公开(写入 _SECRET/password.txt, 已 gitignore)。
  2) 公开分析层  analysis/<label>.json : 纯静态分析衍生物(哈希/大小/magic/节区/导入DLL/top strings/熵),
                                        不含任何可执行字节 —— 物理上无法还原成可运行文件。

用法:
  python3 neutralize_workflow.py --secret-file _SECRET/password.txt        # 生成/复用强密码
  # 处理当前 *_DEFANGED.zip(公开密码 infected)-> 转成 SECURE + analysis
  python3 neutralize_workflow.py --migrate-from-defanged
依赖: pyzipper (pip install pyzipper)

注意: 本脚本只是"当前 commit"的处理。要彻底移除历史里旧的 infected 弱加密版本,
      必须再做 git 历史清除(见 NEUTRALIZATION.md 第四节),否则旧 commit 仍可还原。
"""
import os, sys, json, hashlib, math, glob, secrets, string, argparse, subprocess
try:
    import pyzipper
except ImportError:
    sys.exit("需要 pyzipper: pip install pyzipper")

SAMPLES = os.path.dirname(os.path.abspath(__file__))
ANALYSIS = os.path.join(SAMPLES, "analysis")
SECRET_DIR = os.path.join(SAMPLES, "_SECRET")

def sha256(b): return hashlib.sha256(b).hexdigest()
def md5(b): return hashlib.md5(b).hexdigest()

def entropy(b):
    if not b: return 0.0
    freq = [0]*256
    for x in b: freq[x]+=1
    e=0.0; n=len(b)
    for c in freq:
        if c: p=c/n; e-=p*math.log2(p)
    return round(e,3)

def top_strings(b, minlen=6, limit=400):
    out=[]; cur=bytearray()
    for x in b:
        if 32<=x<127: cur.append(x)
        else:
            if len(cur)>=minlen: out.append(cur.decode('ascii','ignore'))
            cur=bytearray()
    if len(cur)>=minlen: out.append(cur.decode('ascii','ignore'))
    # 去重保序 + 截断
    seen=set(); uniq=[]
    for s in out:
        if s not in seen:
            seen.add(s); uniq.append(s)
        if len(uniq)>=limit: break
    return uniq

def pe_light(b):
    """极简 PE 解析: 只取对行为分析有用的元数据, 不重建可执行结构。"""
    info={"is_pe": False}
    if len(b)<0x40 or b[:2]!=b'MZ': return info
    try:
        e_lfanew=int.from_bytes(b[0x3c:0x40],'little')
        if b[e_lfanew:e_lfanew+4]!=b'PE\x00\x00': return info
        info["is_pe"]=True
        coff=e_lfanew+4
        machine=int.from_bytes(b[coff:coff+2],'little')
        nsec=int.from_bytes(b[coff+2:coff+4],'little')
        info["machine"]=hex(machine); info["num_sections"]=nsec
        opt=coff+20
        magic=int.from_bytes(b[opt:opt+2],'little')
        info["pe_type"]="PE32+" if magic==0x20b else "PE32"
        # 导入的 DLL 名(从 strings 里筛, 供行为参考; 不做完整导入表重建)
        dlls=sorted({s.lower() for s in top_strings(b,4,3000) if s.lower().endswith('.dll')})
        info["imported_dll_guess"]=dlls[:60]
    except Exception as ex:
        info["parse_error"]=str(ex)[:60]
    return info

def make_analysis(label, data, meta):
    os.makedirs(ANALYSIS, exist_ok=True)
    rec={
        "label": label,
        "family": meta.get("brand",""),
        "platform": meta.get("platform",""),
        "original_sha256": meta.get("original_sha256",""),
        "original_size": meta.get("original_size", len(data)),
        "magic_first4_hex": data[:4].hex(),
        "entropy": entropy(data[:1<<20]),
        "md5": md5(data),
        "strings_top": top_strings(data),
        "pe": pe_light(data),
        "note": "静态分析衍生物;不含可执行字节;不可还原为可运行文件。",
    }
    with open(os.path.join(ANALYSIS, f"{label}.json"),"w",encoding="utf-8") as f:
        json.dump(rec,f,ensure_ascii=False,indent=2)

def secure_zip(label, defanged_bytes, password):
    """把(已破坏文件头的)完整样本用 AES-256 + 强密码封装。"""
    z=os.path.join(SAMPLES, f"{label}_SECURE.zip")
    if os.path.exists(z): os.remove(z)
    tmp=os.path.join(SAMPLES, f".__{label}.def")
    open(tmp,"wb").write(defanged_bytes)
    with pyzipper.AESZipFile(z,'w',compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode()); zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.write(tmp, arcname=f"{label}.defanged.bin")
    os.remove(tmp)
    # 分卷(>95MB)
    if os.path.getsize(z)>95*1024*1024:
        subprocess.run(["split","-b","90m","-d",z,z+".part"],check=True); os.remove(z)

def get_or_make_password(path):
    if os.path.exists(path):
        return open(path).read().strip()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    alphabet=string.ascii_letters+string.digits+"!@#$%^&*-_=+"
    pw="".join(secrets.choice(alphabet) for _ in range(40))
    open(path,"w").write(pw+"\n"); os.chmod(path,0o600)
    return pw

def reassemble(base):
    parts=sorted(glob.glob(base+".part*"))
    if parts:
        with open(base,"wb") as out:
            for p in parts: out.write(open(p,"rb").read())
    return base

def migrate(password):
    man={m["label"]:m for m in json.load(open(os.path.join(SAMPLES,"MANIFEST.json")))}
    done=0
    for zf in sorted(glob.glob(os.path.join(SAMPLES,"*_DEFANGED.zip"))+glob.glob(os.path.join(SAMPLES,"*_DEFANGED.zip.part00"))):
        base=zf[:-7] if zf.endswith(".part00") else zf
        base=reassemble(base) if zf.endswith(".part00") else base
        label=os.path.basename(base).replace("_DEFANGED.zip","")
        try:
            with pyzipper.AESZipFile(base) as z:
                z.setpassword(b'infected'); name=z.namelist()[0]; defanged=z.read(name)
        except Exception:
            # 旧的是 ZipCrypto(zip -P), 用标准库
            import zipfile
            with zipfile.ZipFile(base) as z:
                defanged=z.read(z.namelist()[0], pwd=b'infected')
        meta=man.get(label,{})
        # 还原真实首4字节仅用于生成"分析衍生物"(在内存里, 不落盘可运行文件)
        real=bytearray(defanged); r=meta.get("defang_restore_first4_hex")
        if r and len(r)==8: real[0:4]=bytes.fromhex(r)
        make_analysis(label, bytes(real), meta)
        # SECURE 层用"破坏文件头"的版本(defanged), AES+强密码
        secure_zip(label, defanged, password)
        done+=1
        print(f"  [{done}] {label} -> SECURE + analysis", flush=True)
    print(f"完成 {done} 个样本")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--secret-file", default=os.path.join(SECRET_DIR,"password.txt"))
    ap.add_argument("--migrate-from-defanged", action="store_true")
    a=ap.parse_args()
    pw=get_or_make_password(a.secret_file)
    print(f"强密码文件: {a.secret_file} (已 gitignore, 请勿提交)")
    if a.migrate_from_defanged:
        migrate(pw)
