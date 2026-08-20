from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANNOTATION_DIR = ROOT / "evaluation" / "annotations"
FILES = [ANNOTATION_DIR / "annotator_a.jsonl", ANNOTATION_DIR / "annotator_b.jsonl"]
REVIEWED_AT = "2026-08-02T20:15:00+08:00"


def confirm(path: Path) -> None:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    metadata = rows[0]
    slot = metadata.get("annotator_id", path.stem)
    metadata["status"] = "review_confirmed_by_user"
    metadata["reviewer_id"] = "user_in_thread"
    metadata["reviewed_at"] = REVIEWED_AT
    metadata["review_result"] = "confirmed_without_changes"
    metadata["independence_note"] = "Both files were confirmed in the same user review; do not treat them as independent dual annotations for Kappa."

    for row in rows[1:]:
        annotation = row["annotation"]
        annotation["review_status"] = "confirmed"
        annotation["reviewer_id"] = "user_in_thread"
        annotation["reviewed_at"] = REVIEWED_AT
        annotation["notes"] = (
            f"Codex预标注已由用户确认无误；保留为标注槽位 {slot} 的审核结果。"
            "本次确认不构成两名独立标注员的独立判断。"
        )

    path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")


def main() -> None:
    for path in FILES:
        confirm(path)
        print(path)


if __name__ == "__main__":
    main()
