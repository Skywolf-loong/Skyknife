"""
Auditor —— 审核者（每个任务一个，规则驱动、零 LLM 依赖）。

职责（对标红队报告审核环节）：
1. **去重**：同资产同漏洞只留一条——CVE 优先归并，无 CVE 用归一化标题归并；
2. **去假**：无证据 / 证据与标题同文的发现标记为可疑，不计入漏洞数；
3. **结束判断**：结合剩余攻击面（资产覆盖度）、无新增产出的连续轮数、
   token 消耗与预算，给出 continue / finish 建议。

审核不删除数据（可追溯）：重复项打 ``audit_status=duplicate``（merged_into 指向
保留项），假阳性打 ``audit_status=fake``；报告与前端统计自动排除这两类。
"""
import re
from typing import Dict, List

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_SEV_RANK = {"危急": 0, "高": 1, "中": 2, "低": 3}


def _norm_title(label: str) -> str:
    """归一化标题：去空白/标点/版本号差异，保留中英文主体。"""
    s = (label or "").lower()
    s = re.sub(r"cve-\d{4}-\d{4,7}", "", s)
    s = re.sub(r"[\s\d.（）()\[\]【】：:，,。·\-_/\\|'\"`～~*#?！!]+", "", s)
    return s


class Auditor:
    """规则审核器。audit() 幂等：重复审核不产生新动作。"""

    def audit(self, findings: List[dict], coverage: Dict = None,
              tokens: Dict = None, token_budget: int = 0,
              stale_rounds: int = 0) -> Dict:
        findings = findings or []
        # ---- 1. 去重：CVE 优先，其次归一化标题，均结合资产 ----
        groups: Dict[tuple, List[dict]] = {}
        for f in findings:
            data = f.get("data") or {}
            label = f.get("label", "")
            asset = (f.get("asset_ref") or data.get("asset") or "").strip().lower()
            cves = tuple(sorted({c.upper() for c in _CVE_RE.findall(label)}))
            if cves:
                key = ("cve", cves, asset)
            else:
                key = ("t", _norm_title(label), asset)
            groups.setdefault(key, []).append(f)

        duplicates: List[Dict] = []       # [{drop_id, keep_id, reason}]
        fake: List[Dict] = []             # [{id, reason}]
        dup_ids = set()
        for key, grp in groups.items():
            if len(grp) < 2:
                continue
            def _rank(f):
                d = f.get("data") or {}
                return (-len((d.get("evidence") or "").strip()),
                        _SEV_RANK.get(d.get("severity", "中"), 9))
            grp_sorted = sorted(grp, key=_rank)
            keep = grp_sorted[0]
            tag = f"CVE {key[1][0]}" if key[0] == "cve" else "同类漏洞"
            for d in grp_sorted[1:]:
                dup_ids.add(d["id"])
                duplicates.append({
                    "drop_id": d["id"], "keep_id": keep["id"],
                    "reason": f"同资产重复{tag}（与 {keep['id']} 归并）",
                })

        # ---- 2. 去假：无可验证证据 ----
        for f in findings:
            fid = f["id"]
            if fid in dup_ids:
                continue
            data = f.get("data") or {}
            ev = (data.get("evidence") or "").strip()
            title = (f.get("label") or "").strip()
            if not ev or ev == title:
                fake.append({"id": fid,
                             "reason": "无可验证证据（evidence 为空或与标题相同）"})

        # ---- 3. 结束判断：剩余攻击面 + 停滞轮数 + token 预算 ----
        coverage = coverage or {}
        tokens = tokens or {}
        cov_ratio = float(coverage.get("coverage") or 0)
        uncovered = int(coverage.get("uncovered") or 0)
        reasons = []
        if stale_rounds >= 2:
            reasons.append(f"连续 {stale_rounds} 轮无新增事实/漏洞（攻击面已穷尽）")
        if uncovered == 0 and findings and cov_ratio >= 0.5:
            reasons.append(f"资产已全覆盖（覆盖率 {cov_ratio:.0%}）且无新攻击面")
        if token_budget and tokens.get("total", 0) >= token_budget:
            reasons.append(f"token 消耗 {tokens.get('total')} 达到预算 {token_budget}")
        verdict = "finish" if reasons else "continue"

        return {
            "verdict": verdict,
            "reason": "；".join(reasons) if reasons else "仍有可推进的攻击面",
            "duplicates": duplicates,
            "fake": fake,
            "kept": len(findings) - len(duplicates) - len(fake),
            "coverage": {"coverage": cov_ratio, "uncovered": uncovered},
            "tokens": {"total": tokens.get("total", 0),
                       "budget": token_budget or None},
        }

    @staticmethod
    def visible(findings: List[dict]) -> List[dict]:
        """过滤掉被审核剔除的发现（报告/统计用）。"""
        out = []
        for f in findings or []:
            st = (f.get("data") or {}).get("audit_status")
            if st in ("duplicate", "fake"):
                continue
            out.append(f)
        return out
