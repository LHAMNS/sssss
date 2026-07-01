#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QuickQ 生态 YARA 扫描器 (MAL-2026-0301)
用法: python3 scan.py <目录或文件> [<目录或文件> ...]
特点: 自动为每个文件传入 `filename` 外部变量,使"伪装扩展名"规则正确判定。
依赖: pip install yara-python
"""
import sys, os, yara

RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quickq_ecosystem.yar")

def main(paths):
    rules = yara.compile(RULES, externals={"filename": ""})
    hits = 0; scanned = 0
    for root in paths:
        files = []
        if os.path.isdir(root):
            for dp, _, fns in os.walk(root):
                files += [os.path.join(dp, fn) for fn in fns]
        else:
            files = [root]
        for f in files:
            try:
                m = rules.match(f, externals={"filename": os.path.basename(f)})
            except Exception as e:
                print(f"  [ERR] {f}: {e}"); continue
            scanned += 1
            if m:
                hits += 1
                print(f"[HIT] {f}")
                for x in m:
                    print(f"       -> {x.rule}  ({x.meta.get('family', x.meta.get('desc',''))[:60]})")
    print(f"\n扫描 {scanned} 文件,命中 {hits}。")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
