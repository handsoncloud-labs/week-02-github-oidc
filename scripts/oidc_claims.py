#!/usr/bin/env python3
"""Print the claims in this job's GitHub OIDC token. Runs inside Actions.

Never prints the token itself; it is masked in the log first.
"""

import base64
import json
import os
import urllib.request

url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
if not url or not bearer:
    raise SystemExit("No OIDC token available: the job needs `permissions: id-token: write`.")

req = urllib.request.Request(f"{url}&audience=sts.amazonaws.com", headers={"Authorization": f"bearer {bearer}"})
token = json.load(urllib.request.urlopen(req, timeout=20))["value"]
print(f"::add-mask::{token}")

payload = token.split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
for key in ("iss", "aud", "sub", "repository", "ref", "workflow"):
    print(f"CLAIM {key}={claims.get(key)}")
