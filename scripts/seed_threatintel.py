import json
import re
from pathlib import Path

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from run import app

from app.extensions import db
from app.threatintel.models import (
    IOC,
    ThreatCampaign,
    ThreatFeed,
)


DATA_FILE = (
    Path(__file__).resolve().parent.parent
    / "app"
    / "static"
    / "js"
    / "data"
    / "threat-data.js"
)


def load_js_array(text, variable_name):
    pattern = rf"const\s+{re.escape(variable_name)}\s*=\s*(\[.*?\]);"
    match = re.search(pattern, text, re.DOTALL)

    if not match:
        raise RuntimeError(
            f"Could not find {variable_name} in {DATA_FILE}"
        )

    return json.loads(match.group(1))


def seed_iocs(data):
    created = 0
    skipped = 0

    for item in data:
        existing = IOC.query.filter_by(ioc_id=item["id"]).first()

        if existing:
            skipped += 1
            continue

        ioc = IOC(
            ioc_id=item["id"],
            value=item["value"],
            type=item["type"],
            threat_level=item["threatLevel"],
            confidence=item["confidence"],
            source=item["source"],
            first_seen=item["firstSeen"],
            last_seen=item["lastSeen"],
            sightings=item["sightings"],
            tags=json.dumps(item.get("tags", [])),
            campaign_id=item.get("campaignId"),
            campaign_name=item.get("campaignName"),
            status=item["status"],
        )

        db.session.add(ioc)
        created += 1

    return created, skipped


def seed_campaigns(data):
    created = 0
    skipped = 0

    for item in data:
        existing = ThreatCampaign.query.filter_by(
            campaign_id=item["id"]
        ).first()

        if existing:
            skipped += 1
            continue

        campaign = ThreatCampaign(
            campaign_id=item["id"],
            name=item["name"],
            actor_id=item.get("actorId"),
            actor_name=item.get("actorName"),
            status=item["status"],
            first_observed=item["firstObserved"],
            target_sectors=json.dumps(item.get("targetSectors", [])),
            ioc_count=item.get("iocCount", 0),
            ttps=json.dumps(item.get("ttps", [])),
            description=item.get("description"),
        )

        db.session.add(campaign)
        created += 1

    return created, skipped


def seed_feeds(data):
    created = 0
    skipped = 0

    for item in data:
        existing = ThreatFeed.query.filter_by(
            feed_id=item["id"]
        ).first()

        if existing:
            skipped += 1
            continue

        feed = ThreatFeed(
            feed_id=item["id"],
            name=item["name"],
            provider=item["provider"],
            feed_type=item["type"],
            status=item["status"],
            ioc_count=item.get("iocCount", 0),
            last_sync=item["lastSync"],
            reliability=item["reliability"],
        )

        db.session.add(feed)
        created += 1

    return created, skipped


def main():
    print("=" * 60)
    print("CyberDefense XDR - Threat Intelligence Seeder")
    print("=" * 60)

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Threat Intelligence data file not found:\n{DATA_FILE}"
        )

    text = DATA_FILE.read_text(encoding="utf-8")

    iocs = load_js_array(text, "IOCS_DATA")
    campaigns = load_js_array(text, "CAMPAIGNS_DATA")
    feeds = load_js_array(text, "FEEDS_DATA")

    print(f"Loaded IOC records:       {len(iocs)}")
    print(f"Loaded campaign records:  {len(campaigns)}")
    print(f"Loaded feed records:      {len(feeds)}")
    print()

    with app.app_context():
        ioc_created, ioc_skipped = seed_iocs(iocs)
        campaign_created, campaign_skipped = seed_campaigns(campaigns)
        feed_created, feed_skipped = seed_feeds(feeds)

        db.session.commit()

        print("Database seeding completed.")
        print()
        print(f"IOCs       → created: {ioc_created}, skipped: {ioc_skipped}")
        print(
            f"Campaigns  → created: {campaign_created}, "
            f"skipped: {campaign_skipped}"
        )
        print(f"Feeds      → created: {feed_created}, skipped: {feed_skipped}")


if __name__ == "__main__":
    main()
