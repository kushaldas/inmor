import json
import sys
from datetime import datetime, timedelta

from django.conf import settings
from jwcrypto import jwk, jwt

import redis


def add_trustmark(entity: str, trustmarktype: str, r: redis.Redis) -> str:
    """Adds a new subordinate to the federation.

    :args entity_id: The entity_id to be added
    """
    # Based on https://openid.net/specs/openid-federation-1_0.html#name-trust-marks

    # This is the data we care for now
    sub_data = {"iss": "http://localhost:8080"}
    sub_data["sub"] = entity
    now = datetime.now()
    exp = now + timedelta(days=365)
    sub_data["iat"] = now.timestamp()
    sub_data["exp"] = exp.timestamp()
    # TODO: ref: we have to add this claim too in future
    sub_data["trust_mark_type"] = trustmarktype

    key = settings.SIGNING_PRIVATE_KEY

    # TODO: fix the alg value for other types of keys of TA/I
    token = jwt.JWT(header={"alg": "RS256", "kid": key.kid}, claims=sub_data)
    token.make_signed_token(key)
    token_data = token.serialize()
    # Now we should set it in the redis
    # First, the trustmark for the entity and that trustmarktype
    r.hset(f"inmor:tm:{entity}", trustmarktype, token_data)
    # second, add to the set of trust_mark_type
    r.sadd(f"inmor:tmtype:{trustmarktype}", entity)
    return token_data
