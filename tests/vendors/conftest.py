import os

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "postgresql://soc:soc@localhost:5432/soc")

KEYS = "feed-key:feed;agent-key:read;exec-key:respond;sensor-key:ingest"
FEED = {"X-Api-Key": "feed-key"}
READ = {"X-Api-Key": "agent-key"}
RESPOND = {"X-Api-Key": "exec-key"}
INGEST = {"X-Api-Key": "sensor-key"}
