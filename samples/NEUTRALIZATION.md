# 样本统一中和方案（发布前必读）

**目标:** 上传到(可能公开的)仓库的样本,**只能用于分析行为与手法,不能被直接运行,也不能被方便地还原/改造成可用恶意软件**。重点是"行为和方式",不是提供可运行的东西。

---

## 一、两层模型

| 层 | 文件 | 加密 | 密码 | 含可执行字节? | 能否还原运行 |
|----|------|------|------|--------------|-------------|
| **① 内部完整层** | `<label>_SECURE.zip`(>95MB 分卷) | **AES-256** | **强随机 40 位,不公开**(`_SECRET/password.txt`,已 gitignore) | 是(但**文件头已破坏**) | 仅持密码的团队:解密→补回首4字节→可运行 |
| **② 公开分析层** | `analysis/<label>.json` | 无 | 公开 | **否** | **不可能**(根本没有二进制) |

**为什么公开层不放"换密码的加密二进制":**
只要是"加密二进制 + 已知密码",就等于把马直接发出去了。真正安全的公开形式是**不含可执行字节的静态衍生物**——它满足"只看行为/手法",且**物理上无法拿去造马**。

**公开层 `analysis/*.json` 包含(足够做行为研究):**
- 原始 SHA256/MD5、大小、magic 首4字节、熵值
- PE 元数据:类型(PE32/PE32+)、节区数、导入 DLL 名(行为线索)
- Top strings(API 名、URL、命令、配置串——行为的核心证据)
- 家族/平台/来源标注

---

## 二、"破坏"的具体做法(双重 + 强加密)

1. **文件头破坏(defang)**:首 4 字节清零,毁掉 PE `MZ`/ZIP `PK`/DMG magic → 双击/加载器均不识别。原始首4字节记录在 `MANIFEST.csv`(仅内部还原用)。
2. **强 AES-256 加密 + 不公开密码**:内部完整层即使被拿到,没有那串 40 位随机密码也解不开;解开后还得补文件头才可运行——两道关。
3. **公开层无可执行字节**:根本不给二进制。

> 组合效果:公开层=零武器化风险;内部完整层=非持密码者无法运行,持密码团队可完整静/动态分析。

---

## 三、工作流工具

`neutralize_workflow.py`(需 `pip install pyzipper`):
```bash
# 生成强密码(写入 _SECRET/password.txt, 已 gitignore)并把所有 *_DEFANGED.zip 迁移为两层
python3 neutralize_workflow.py --migrate-from-defanged
```
产出:每个样本 → `<label>_SECURE.zip`(AES+强密码) + `analysis/<label>.json`(公开)。旧的 `*_DEFANGED.zip`(公开密码 infected)删除。

---

## 四、⚠️ Git 历史清除(关键,否则前功尽弃)

即使这一 commit 换成强加密,**旧的 `infected` 弱加密版本仍永久留在 git 历史**里(`git checkout <旧commit>` 即可还原)。彻底方案二选一:

**A. 全新孤儿分支(推荐,最干净):**
```bash
git checkout --orphan clean-public
git add -A && git commit -m "Neutralized public release (no history)"
# 用它作为对外发布分支;不推送含旧历史的分支
```
**B. 历史重写(git filter-repo):**
```bash
pip install git-filter-repo
git filter-repo --path-glob 'samples/*_DEFANGED.zip*' --invert-paths
git filter-repo --path-glob 'samples/*_INFECTED.zip*' --invert-paths
# 强制推送重写后的历史
```
> 本仓库尚未公开(用户确认),历史清除由用户执行。发布前务必完成 A 或 B,并确认 `_SECRET/` 未被提交。

---

## 五、发布前检查清单
- [ ] `_SECRET/password.txt` 在 `.gitignore` 中且未被 `git add`(`git log --all -- samples/_SECRET/` 应为空)
- [ ] 仓库内无 `*_DEFANGED.zip` / `*_INFECTED.zip`(公开密码版本)残留
- [ ] 历史已按第四节清除(孤儿分支或 filter-repo)
- [ ] 公开层 `analysis/*.json` 不含可执行字节(设计如此)
- [ ] 强密码通过**带外渠道**单独交付给需要完整样本的团队,绝不进仓库
