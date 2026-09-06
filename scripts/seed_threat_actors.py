import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from run import app
from app.extensions import db
from app.threatintel.models import ThreatActor


DATA_FILE = (
    PROJECT_ROOT
    / "app"
    / "static"
    / "js"
    / "data"
    / "actors-data.js"
)


def load_actors():
    text = DATA_FILE.read_text(encoding="utf-8")

    match = re.search(
        r"const\s+ACTORS_DATA\s*=\s*(\[.*?\]);",
        text,
        re.DOTALL,
    )

    if not match:
        raise RuntimeError(
            f"Could not find ACTORS_DATA in {DATA_FILE}"
        )

    return json.loads(match.group(1))


def seed_actors(actors):
    created = 0
    skipped = 0

    for item in actors:
        existing = ThreatActor.query.filter_by(
            actor_id=item["id"]
        ).first()

        if existing:
            skipped += 1
            continue

        actor = ThreatActor(
            actor_id=item["id"],
            name=item["name"],
            origin=item.get("origin"),
            sophistication=item.get("sophistication"),
            motivation=item.get("motivation"),
            campaign_count=item.get("campaignCount", 0),
            last_activity=item.get("lastActivity"),
            first_seen=item.get("firstSeen"),
            description=item.get("description"),
            target_sectors=json.dumps(
                item.get("targetSectors", [])
            ),
            mitre_tactics=json.dumps(
                item.get("mitreTactics", [])
            ),
        )

        db.session.add(actor)
        created += 1

    return created, skipped


def main():
    print("=" * 60)
    print("CyberDefense XDR - Threat Actor Seeder")
    print("=" * 60)

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Actor data file not found:\n{DATA_FILE}"
        )

    actors = load_actors()

    print(f"Loaded actor records: {len(actors)}")
    print()

    with app.app_context():
        created, skipped = seed_actors(actors)

        db.session.commit()

        print("Database seeding completed.")
        print()
        print(f"Actors → created: {created}, skipped: {skipped}")


if __name__ == "__main__":
    main()
