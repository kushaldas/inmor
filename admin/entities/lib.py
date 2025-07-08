import json
from datetime import datetime

import httpx
from django.conf import settings
from jwcrypto import jwt

from redis import Redis


def add_subordinate(entity_id: str, r: Redis):
    """Adds a new subordinate to the federation.

    :args entity_id: The entity_id to be added
    :args r: Redis class from Django
    """
    resp = httpx.get(f"{entity_id}/.well-known/openid-federation")
    text = resp.text
    jwt_net = jwt.JWT.from_jose_token(text)
    # FIXME: In future we will need the proper key to verify the signature and use only
    # validated contain.
    payload = json.loads(jwt_net.token.objects.get("payload").decode("utf-8"))

    # TODO: Verify that the authority_hints matches with the inmor's entity_id.

    # This is the data we care for now
    sub_data = {"iss": "http://localhost:8080"}
    sub_data["jwks"] = payload.get("jwks")
    sub_data["authority_hints"] = payload.get("authority_hints")
    metadata = payload.get("metadata")
    if metadata:
        sub_data["metadata"] = metadata

    # FIXME: Add the TA/I's metadata_policy here.
    # sub_data["metadata_policy "]= metadata_policy

    trust_marks = payload.get("trust_marks")
    if trust_marks:
        sub_data["trust_marks"] = trust_marks
    sub_data["exp"] = payload.get("exp")
    sub_data["sub"] = payload.get("sub")
    # creation time
    sub_data["iat"] = datetime.now().timestamp()

    key = settings.SIGNING_PRIVATE_KEY

    # TODO: fix the alg value for other types of keys of TA/I
    token = jwt.JWT(header={"alg": "RS256", "kid": key.kid}, claims=sub_data)
    token.make_signed_token(key)
    token_data = token.serialize()
    # Now we should set it in the redis
    r.hset("inmor:subordinates", sub_data["sub"], token_data)
    # FIXME: Next to set in the queue for discovering the tree
