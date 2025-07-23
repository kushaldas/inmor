import json
import logging
import os
from datetime import datetime
from typing import Any, cast

import httpx
from django.conf import settings
from jwcrypto import jwt
from jwcrypto.jwk import JWK, JWKSet
from jwcrypto.jwt import JWT
from pydantic import BaseModel

from redis import Redis

INSIDE_CONTAINER = os.environ.get("INSIDE_CONTAINER")

logger = logging.getLogger(__name__)


class SubordinateRequest(BaseModel):
    entity: str


def add_subordinate(entity_id: str, r: Redis) -> str:
    """Adds a new subordinate to the federation.

    This creates a subordinate statement by the TA as iss and adds the metadata of the entity (subordinate).
    https://openid.net/specs/openid-federation-1_0.html#name-fetch-subordinate-statement-

    :args entity_id: The entity_id to be added
    :args r: Redis class from Django

    :returns: String version of the signed JWT
    """
    resp = httpx.get(f"{entity_id}/.well-known/openid-federation")
    text = resp.text
    jwt_net: JWT = jwt.JWT.from_jose_token(text)
    # FIXME: In future we will need the proper key to verify the signature and use only
    # validated contain.
    payload = json.loads(jwt_net.token.objects.get("payload").decode("utf-8"))

    # TODO: Verify that the authority_hints matches with the inmor's entity_id.

    # This is the data we care for now
    sub_data = {"iss": settings.TA_DOMAIN}
    # We don't need this for subordinate statement
    # sub_data["authority_hints"] = payload.get("authority_hints")
    metadata = payload.get("metadata")
    if metadata:
        sub_data["metadata"] = metadata

    # This is the metadata policy of TA defined in the settings.py
    sub_data["metadata_policy "] = settings.METADATA_POLICY

    # We don't need trustmarks for the subordinate statements.
    # trust_marks = payload.get("trust_marks")
    # if trust_marks:
    # sub_data["trust_marks"] = trust_marks

    # Default we keep the same expiry of the subordinate entity configuration
    sub_data["exp"] = payload.get("exp")
    sub_data["sub"] = payload.get("sub")
    # creation time
    sub_data["iat"] = datetime.now().timestamp()
    sub_data["jwks"] = [settings.SIGNING_PUBLIC_KEY]

    key = settings.SIGNING_PRIVATE_KEY

    # TODO: fix the alg value for other types of keys of TA/I
    token = jwt.JWT(
        header={"alg": "RS256", "kid": key.kid, "typ": "entity-statement+jwt"}, claims=sub_data
    )
    token.make_signed_token(key)
    token_data = token.serialize()
    # Now we should set it in the redis
    _ = r.hset("inmor:subordinates", sub_data["sub"], token_data)
    # Add the entity in the queue for walking the tree (if any)
    _ = r.lpush("inmor:newsubordinate", entity_id)
    return token_data


def self_validate(token: jwt.JWT) -> dict[str, Any]:
    """Self validates a JWT with JWKS from it."""
    try:
        payload = json.loads(token.token.objects.get("payload").decode("utf-8"))
        # First get the jwks for self-verification
        jwks_set = JWKSet()
        keys = payload.get("jwks").get("keys")
        for key in keys:
            k = JWK(**key)
            jwks_set.add(k)
        token.validate(jwks_set)
        return payload
    except Exception as e:
        raise Exception(str(e))


def fetch_payload(entity_id: str):
    """Fetches entity and validates and returns payload and JWT token as string"""
    resp = httpx.get(f"{entity_id}/.well-known/openid-federation")
    if resp.status_code != 200:
        raise Exception(f"Fetching payload returns {resp.status_code} for {entity_id}")
    text = resp.text
    jwt_net: jwt.JWT = jwt.JWT.from_jose_token(text)
    # FIXME: In future we will need the proper key to verify the signature and use only
    # validated contain.
    payload = self_validate(jwt_net)
    return payload, text


def fetch_subordinate_statements(authority_hints: list[str], entity_id: str, r: Redis):
    """Fetches subordinate statements from the authority hints.

    :args authority_hints: A list of authority hints from entity config.
    :args entity_id: str value of the entity.
    :args r: Redis client instance.
    """
    print(authority_hints)
    print(f"Entity is: {entity_id}")
    for ahint in authority_hints:
        # HACK: To enable fetching from TA container.
        # Special code to identify if we running inside of the container
        # and we have an authority pointing to localhost, then point to ta container
        if INSIDE_CONTAINER and ahint.find("http://localhost:8080") != -1:
            ahint = ahint.replace("localhost", "ta")
            logger.info(f"Replaced to {ahint}")
        # First fetch the entity configuration of the authority & self verify
        try:
            payload, _jwt_net = fetch_payload(ahint)
        except Exception as e:
            logger.error(
                f"Failed to validate {entity_id} wtih error {e} while doing subordinate statement entry."
            )
            continue

        fetch_endpoint = (
            payload.get("metadata", {})
            .get("federation_entity", {})
            .get("federation_fetch_endpoint")
        )
        if fetch_endpoint:
            # HACK: To enable fetching from TA container.
            # Special code to identify if we running inside of the container
            # and we have an authority pointing to localhost, then point to ta container
            if INSIDE_CONTAINER and fetch_endpoint.find("http://localhost:8080") != -1:
                fetch_endpoint = fetch_endpoint.replace("localhost", "ta")
                logger.info(f"Replaced to {fetch_endpoint}")
            # We have a fetch endpoint
            url = f"{fetch_endpoint}/?sub={entity_id}"
            logger.info(f"Fetching subordinate statement: {url}")
            resp = httpx.get(url)
            if resp.status_code != 200:
                logger.warning(
                    f"Fetching subordinate statement returns {resp.status_code} for {entity_id}"
                )
                continue
            text = resp.text
            if text:
                # now we can just set that for future calls
                _ = r.hset("inmor:subordinate_query", url, text)


def tree_walking(entity_id: str, r: Redis, visited: set[str] | None = None):
    """Discovers a tree from the given entity_id.

    :args entity_id: The entity_id to be added
    :args visited: An optional set of entities already visited
    """
    if not visited:
        visited = set()
    try:
        payload, jwt_net = fetch_payload(entity_id)
    except Exception as e:
        logger.error(f"Failed to validate {entity_id} wtih error {e}")
        return visited
    # Add to the visited list
    visited.add(entity_id)
    # Add to the entity hash in redis
    _ = r.hset("inmor:entities", entity_id, jwt_net)

    # Visit authorities for subordinate statements
    authority_hints = payload.get("authority_hints")
    if authority_hints:
        fetch_subordinate_statements(authority_hints, entity_id, r)

    # Now the actual discovery
    metadata = cast(dict[str, Any], payload.get("metadata"))
    if "openid_relying_party" in metadata:
        # Mweans RP
        _ = r.sadd("inmor:rp", entity_id)
        logger.info(f"{entity_id} added as RP to memory database.")
    elif "openid_provider" in metadata:
        # Means  OP
        _ = r.sadd("inmor:op", entity_id)
        logger.info(f"{entity_id} added as OP to memory database.")
    else:  # means "federation_entity" in metadata:
        # Means we have a TA/IA
        _ = r.sadd("inmor:taia", entity_id)
        list_endpoint = metadata["federation_entity"].get("federation_list_endpoint")
        if not list_endpoint:
            logger.warning(f"{entity_id} does not have a list endpoint")
            return visited
        resp = httpx.get(list_endpoint)
        subordinates = json.loads(resp.text)
        for subordinate in subordinates:
            if subordinate in visited:
                # Means we already visited it, it is a loop.
                # We should skip it.
                logger.warning
                (f"LOOP DETECTED: Found {subordinate} but already visited, means LOOP.")
                continue
            logger.info(f"Found {subordinate}")
            # Now visit that suboridnate
            visited.update(tree_walking(subordinate, r, visited))

    # return the already visited set
    return visited


# jwcrypto.jws.InvalidJWSSignature

if __name__ == "__main__":
    r = Redis("redis")
    logging.basicConfig(level=logging.INFO)
    _ = tree_walking("", r)
