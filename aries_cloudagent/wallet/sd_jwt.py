"""Operations supporting SD-JWT creation and verification."""

import json
from typing import Any, List, Mapping, Optional
from jsonpath_ng.ext import parse
from sd_jwt.common import SDObj
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.verifier import SDJWTVerifier

from ..core.profile import Profile
from ..wallet.jwt import JWTVerifyResult, jwt_sign, jwt_verify
from ..core.error import BaseError


class SDJWTError(BaseError):
    """SD-JWT Error."""


class SDJWTIssuerACAPy(SDJWTIssuer):
    """SDJWTIssuer class for ACA-Py implementation."""

    def __init__(
        self,
        user_claims: dict,
        issuer_key,
        holder_key,
        profile: Profile,
        headers: dict,
        did: Optional[str] = None,
        verification_method: Optional[str] = None,
        add_decoy_claims: bool = False,
        serialization_format: str = "compact",
    ):
        """Initialize an SDJWTIssuerACAPy instance."""
        self._user_claims = user_claims
        self._issuer_key = issuer_key
        self._holder_key = holder_key

        self.profile = profile
        self.headers = headers
        self.did = did
        self.verification_method = verification_method

        self._add_decoy_claims = add_decoy_claims
        self._serialization_format = serialization_format
        self.ii_disclosures = []

    async def _create_signed_jws(self):
        self.serialized_sd_jwt = await jwt_sign(
            self.profile,
            self.headers,
            self.sd_jwt_payload,
            self.did,
            self.verification_method,
        )

    async def issue(self):
        """Issue an sd-jwt."""
        self._check_for_sd_claim(self._user_claims)
        self._assemble_sd_jwt_payload()
        await self._create_signed_jws()
        self._create_combined()


def sort_sd_list(sd_list):
    """
    Sorts sd_list.

    Ensures that selectively disclosable claims deepest
    in the structure are handled first.
    """
    nested_claim_sort = [(len(sd.split(".")), sd) for sd in sd_list]
    nested_claim_sort.sort(reverse=True)
    return [sd[1] for sd in nested_claim_sort]


async def sd_jwt_sign(
    profile: Profile,
    headers: Mapping[str, Any],
    payload: Mapping[str, Any],
    sd_list: List,
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
) -> str:
    """
    Sign sd-jwt.

    Use sd_list to wrap selectively disclosable claims with
    SDObj within payload, create SDJWTIssuerACAPy object, and
    call SDJWTIssuerACAPy.issue().
    """

    sorted_sd_list = sort_sd_list(sd_list)
    for sd in sorted_sd_list:
        jsonpath_expression = parse(f"$.{sd}")
        matches = jsonpath_expression.find(payload)
        if len(matches) < 1:
            raise SDJWTError("Claim for {sd} not found in payload.")
        else:
            for match in matches:
                if type(match.context.value) is list:
                    match.context.value.remove(match.value)
                    match.context.value.append(SDObj(match.value))
                elif type(match.context.value) is str or int or dict or bool:
                    match.context.value[
                        SDObj(str(match.path))
                    ] = match.context.value.pop(str(match.path))
                else:
                    raise SDJWTError(
                        f"Unrecognized type {type(match.context.value)} for {match.path}"
                    )

    sd_jwt_issuer = SDJWTIssuerACAPy(
        user_claims=payload,
        issuer_key=None,
        holder_key=None,
        profile=profile,
        headers=headers,
        did=did,
        verification_method=verification_method,
    )
    await sd_jwt_issuer.issue()
    print(json.dumps(sd_jwt_issuer.sd_jwt_payload, indent=4))

    return sd_jwt_issuer.sd_jwt_issuance


class SDJWTVerifierACAPy(SDJWTVerifier):
    def __init__(
        self,
        profile: Profile,
        sd_jwt_presentation: str,
        serialization_format: str = "compact",
    ):
        self.profile = profile
        self.sd_jwt_presentation = sd_jwt_presentation
        self._serialization_format = serialization_format

    async def _verify_sd_jwt(self):
        return await jwt_verify(
            self.profile,
            self.serialized_sd_jwt,
        )

    def _parse_sd_jwt(self, sd_jwt):
        if self._serialization_format == "compact":
            (
                self._unverified_input_sd_jwt,
                *self._input_disclosures,
                self._unverified_input_key_binding_jwt,
            ) = self._split(sd_jwt)
            return self._unverified_input_sd_jwt

    async def verify(self):
        self.serialized_sd_jwt = self._parse_sd_jwt(self.sd_jwt_presentation)
        self._create_hash_mappings(self._input_disclosures)
        return await self._verify_sd_jwt()


async def sd_jwt_verify(profile: Profile, sd_jwt_presentation: str) -> JWTVerifyResult:
    sd_jwt_verifier = SDJWTVerifierACAPy(profile, sd_jwt_presentation)
    verified = await sd_jwt_verifier.verify()
    return verified.valid
