import json
import sys
from datetime import datetime

import httpx
import redis
from jwcrypto import jwk, jwt


def add_subordinate(entity_id: str):
    """Adds a new subordinate to the federation.

    :args entity_id: The entity_id to be added
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

    # TODO: later we will have to get the key from a configuration file/location
    private_key_data = open("./private.json").read()
    key = jwk.JWK.from_json(private_key_data)

    # TODO: fix the alg value for other types of keys of TA/I
    token = jwt.JWT(header={"alg": "RS256", "kid": key.kid}, claims=sub_data)
    token.make_signed_token(key)
    token_data = token.serialize()
    # Now we should set it in the redis
    # TODO: Use configuration to find the correct redis instance
    r = redis.Redis()
    r.hset("inmor:subordinates", sub_data["sub"], token_data)
    print(f"Successfully added {entity_id}")


def add_sub_main():
    entity_id = sys.argv[1]
    add_subordinate(entity_id)
