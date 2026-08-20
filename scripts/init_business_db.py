from pathlib import Path

from app.clients.mongo_business_utils import init_business_collections, seed_risk_rules_from_json
from app.utils.path_util import PROJECT_ROOT


def main() -> None:
    collections = init_business_collections()
    rules_path = PROJECT_ROOT / "app" / "query_process" / "rules" / "anti_fraud_rules.json"
    seeded_rules = seed_risk_rules_from_json(rules_path)

    print("MongoDB business collections initialized:")
    for name in collections:
        print(f"- {name}")
    print(f"Risk rules upserted: {seeded_rules}")
    print(f"Rules source: {Path(rules_path).resolve()}")


if __name__ == "__main__":
    main()
