import os

from local_ca.api import create_app

app = create_app(
    db_path=os.environ.get("LOCAL_CA_DB", "local_ca.db"),
    key_dir=os.environ.get("LOCAL_CA_KEYS", "ca_keys"),
)
