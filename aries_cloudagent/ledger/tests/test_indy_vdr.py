import json
from aries_cloudagent.messaging.valid import ENDPOINT_TYPE
import pytest

from asynctest import mock as async_mock

import indy_vdr

from ...core.in_memory import InMemoryProfile
from ...indy.issuer import IndyIssuer
from ...wallet.base import BaseWallet
from ...wallet.key_type import KeyType
from ...wallet.did_method import DIDMethod
from ...wallet.did_info import DIDInfo

from ..endpoint_type import EndpointType
from ..indy_vdr import (
    BadLedgerRequestError,
    ClosedPoolError,
    IndyVdrLedger,
    IndyVdrLedgerPool,
    LedgerError,
    LedgerTransactionError,
    Role,
    VdrError,
)


@pytest.fixture()
def ledger():
    profile = InMemoryProfile.test_profile()
    ledger = IndyVdrLedger(IndyVdrLedgerPool("test-ledger"), profile)

    async def open():
        ledger.pool.handle = async_mock.MagicMock(indy_vdr.Pool)

    async def close():
        ledger.pool.handle = None

    with async_mock.patch.object(ledger.pool, "open", open), async_mock.patch.object(
        ledger.pool, "close", close
    ), async_mock.patch.object(
        ledger, "is_ledger_read_only", async_mock.CoroutineMock(return_value=False)
    ):
        yield ledger


@pytest.mark.indy_vdr
class TestIndyVdrLedger:
    @pytest.mark.asyncio
    async def test_aenter_aexit(self, ledger: IndyVdrLedger):
        assert ledger.pool_handle is None

        async with ledger as led:
            assert ledger.pool_handle

        assert ledger.pool_handle is None

    @pytest.mark.asyncio
    async def test_submit_pool_closed(self, ledger: IndyVdrLedger):
        with pytest.raises(ClosedPoolError):
            await ledger._submit("{}")

    @pytest.mark.asyncio
    async def test_submit_signed(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet = (await ledger.profile.session()).wallet
        test_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        test_msg = indy_vdr.ledger.build_get_txn_request(test_did.did, 1, 1)

        async with ledger:
            result = await ledger._submit(
                test_msg, sign=True, taa_accept=False, write_ledger=False
            )
            assert result.get("signature")
            assert result.get("taaAcceptance") is None

            result = await ledger._submit(
                test_msg, sign=True, taa_accept=True, write_ledger=False
            )
            assert result.get("signature")
            assert result.get("taaAcceptance") is None

            ledger.pool_handle.submit_request.assert_not_awaited()
            result = await ledger._submit(test_msg)
            ledger.pool_handle.submit_request.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fetch_txn_author_agreement(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            with async_mock.patch.object(
                ledger.pool_handle,
                "submit_request",
                async_mock.CoroutineMock(
                    side_effect=[
                        {"data": {"aml": ".."}},
                        {"data": {"text": "text", "version": "1.0"}},
                    ]
                ),
            ):
                response = await ledger.fetch_txn_author_agreement()
                assert response == {
                    "aml_record": {"aml": ".."},
                    "taa_record": {
                        "text": "text",
                        "version": "1.0",
                        "digest": ledger.taa_digest("1.0", "text"),
                    },
                    "taa_required": True,
                }

    @pytest.mark.asyncio
    async def test_submit_signed_taa_accept(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet = (await ledger.profile.session()).wallet
        test_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)

        async with ledger:
            test_msg = indy_vdr.ledger.build_get_txn_request(test_did.did, 1, 1)

            await ledger.accept_txn_author_agreement(
                {
                    "text": "txt",
                    "version": "ver",
                    "digest": ledger.taa_digest("ver", "txt"),
                },
                mechanism="manual",
                accept_time=1000,
            )

            result = await ledger._submit(
                test_msg, sign=True, taa_accept=True, write_ledger=False
            )
            assert result.get("signature")
            assert result.get("taaAcceptance")

    @pytest.mark.asyncio
    async def test_submit_unsigned(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            test_msg = indy_vdr.ledger.build_get_txn_request(None, 1, 1)

            result = await ledger._submit(
                test_msg, sign=False, taa_accept=False, write_ledger=False
            )
            assert result.get("signature") is None
            assert result.get("taaAcceptance") is None

            # no public DID
            with pytest.raises(BadLedgerRequestError):
                await ledger._submit(test_msg, sign=True, write_ledger=False)

    @pytest.mark.asyncio
    async def test_submit_unsigned_ledger_transaction_error(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            test_msg = indy_vdr.ledger.build_get_txn_request(None, 1, 1)

            ledger.pool_handle.submit_request.side_effect = VdrError(99, "message")
            with pytest.raises(LedgerTransactionError):
                await ledger._submit(test_msg, sign=False, taa_accept=False)

    @pytest.mark.asyncio
    async def test_txn_endorse(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet = (await ledger.profile.session()).wallet
        test_msg = indy_vdr.ledger.build_get_txn_request(None, 1, 1)

        async with ledger:
            # invalid request
            with pytest.raises(BadLedgerRequestError):
                await ledger.txn_endorse(request_json="{}")

            # no public DID
            with pytest.raises(BadLedgerRequestError):
                await ledger.txn_endorse(request_json=test_msg.body)

            test_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
            test_msg.set_endorser(test_did.did)

            endorsed_json = await ledger.txn_endorse(request_json=test_msg.body)
            body = json.loads(endorsed_json)
            assert test_did.did in body["signatures"]

    @pytest.mark.asyncio
    async def test_send_schema(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet = (await ledger.profile.session()).wallet
        test_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        issuer = async_mock.MagicMock(IndyIssuer)
        issuer.create_schema.return_value = (
            "schema_issuer_did:schema_name:9.1",
            r'{"ver": "1.0", "id": "schema_issuer_did:schema_name:9.1", "name": "schema_name", "version": "9.1", "attrNames": ["a", "b"]}',
        )

        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "txnMetadata": {"seqNo": 1}
            }

            with async_mock.patch.object(
                ledger,
                "check_existing_schema",
                async_mock.CoroutineMock(return_value=None),
            ):
                schema_id, schema_def = await ledger.create_and_send_schema(
                    issuer, "schema_name", "9.1", ["a", "b"]
                )

            issuer.create_schema.assert_awaited_once_with(
                test_did.did, "schema_name", "9.1", ["a", "b"]
            )

            ledger.pool_handle.submit_request.assert_awaited_once()

            assert schema_id == issuer.create_schema.return_value[0]

            # test endorsed
            schema_id, signed_txn = await ledger.create_and_send_schema(
                issuer=issuer,
                schema_name="schema_name",
                schema_version="9.1",
                attribute_names=["a", "b"],
                write_ledger=False,
                endorser_did=test_did.did,
            )
            assert schema_id == issuer.create_schema.return_value[0]
            txn = json.loads(signed_txn["signed_txn"])
            assert txn.get("endorser") == test_did.did
            assert txn.get("signature")

    @pytest.mark.asyncio
    async def test_send_schema_no_public_did(
        self,
        ledger: IndyVdrLedger,
    ):
        issuer = async_mock.MagicMock(IndyIssuer)
        async with ledger:
            with pytest.raises(BadLedgerRequestError):
                schema_id, schema_def = await ledger.create_and_send_schema(
                    issuer, "schema_name", "9.1", ["a", "b"]
                )

    @pytest.mark.asyncio
    async def test_send_schema_already_exists(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet = (await ledger.profile.session()).wallet
        test_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        issuer = async_mock.MagicMock(IndyIssuer)
        issuer.create_schema.return_value = (
            "schema_issuer_did:schema_name:9.1",
            r'{"ver": "1.0", "id": "schema_issuer_did:schema_name:9.1", "name": "schema_name", "version": "9.1", "attrNames": ["a", "b"]}',
        )

        async with ledger:
            with async_mock.patch.object(
                ledger,
                "check_existing_schema",
                async_mock.CoroutineMock(
                    return_value=(
                        issuer.create_schema.return_value[0],
                        {"schema": "result"},
                    )
                ),
            ) as mock_check:
                schema_id, schema_def = await ledger.create_and_send_schema(
                    issuer, "schema_name", "9.1", ["a", "b"]
                )
                assert schema_id == mock_check.return_value[0]
                assert schema_def == mock_check.return_value[1]

    @pytest.mark.asyncio
    async def test_send_schema_ledger_read_only(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet = (await ledger.profile.session()).wallet
        test_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        issuer = async_mock.MagicMock(IndyIssuer)
        issuer.create_schema.return_value = (
            "schema_issuer_did:schema_name:9.1",
            r'{"ver": "1.0", "id": "schema_issuer_did:schema_name:9.1", "name": "schema_name", "version": "9.1", "attrNames": ["a", "b"]}',
        )

        async with ledger:
            ledger.pool.read_only = True
            with async_mock.patch.object(
                ledger,
                "check_existing_schema",
                async_mock.CoroutineMock(return_value=False),
            ), async_mock.patch.object(
                ledger,
                "is_ledger_read_only",
                async_mock.CoroutineMock(return_value=True),
            ):
                with pytest.raises(LedgerError):
                    schema_id, schema_def = await ledger.create_and_send_schema(
                        issuer, "schema_name", "9.1", ["a", "b"]
                    )

    @pytest.mark.asyncio
    async def test_send_schema_ledger_transaction_error(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet = (await ledger.profile.session()).wallet
        test_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        issuer = async_mock.MagicMock(IndyIssuer)
        issuer.create_schema.return_value = (
            "schema_issuer_did:schema_name:9.1",
            r'{"ver": "1.0", "id": "schema_issuer_did:schema_name:9.1", "name": "schema_name", "version": "9.1", "attrNames": ["a", "b"]}',
        )

        async with ledger:
            ledger.pool_handle.submit_request.side_effect = VdrError(99, "message")

            with async_mock.patch.object(
                ledger,
                "check_existing_schema",
                async_mock.CoroutineMock(return_value=False),
            ):
                with pytest.raises(LedgerTransactionError):
                    schema_id, schema_def = await ledger.create_and_send_schema(
                        issuer, "schema_name", "9.1", ["a", "b"]
                    )

    @pytest.mark.asyncio
    async def test_get_schema(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "seqNo": 99,
                "dest": "55GkHamhTU1ZbTbV2ab9DE",
                "data": {
                    "name": "schema_name",
                    "version": "9.1",
                    "attr_names": ["a", "b"],
                },
            }

            result = await ledger.get_schema("55GkHamhTU1ZbTbV2ab9DE:2:schema_name:9.1")
            assert result == {
                "ver": "1.0",
                "id": "55GkHamhTU1ZbTbV2ab9DE:2:schema_name:9.1",
                "name": "schema_name",
                "version": "9.1",
                "attrNames": ["a", "b"],
                "seqNo": 99,
            }

    @pytest.mark.asyncio
    async def test_get_schema_not_found(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {}
            result = await ledger.get_schema("55GkHamhTU1ZbTbV2ab9DE:2:schema_name:9.1")
            assert result is None

    @pytest.mark.asyncio
    async def test_send_credential_definition(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet = (await ledger.profile.session()).wallet
        test_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        schema_id = "55GkHamhTU1ZbTbV2ab9DE:2:schema_name:9.1"
        cred_def_id = "55GkHamhTU1ZbTbV2ab9DE:3:CL:99:tag"
        cred_def = {
            "ver": "1.0",
            "id": cred_def_id,
            "schemaId": schema_id,
            "type": "CL",
            "tag": "tag",
            "value": {
                "primary": {
                    "n": "...",
                    "s": "...",
                    "r": "...",
                    "revocation": None,
                }
            },
        }
        issuer = async_mock.MagicMock(IndyIssuer)
        issuer.make_credential_definition_id.return_value = cred_def_id
        issuer.credential_definition_in_wallet.return_value = False
        issuer.create_and_store_credential_definition.return_value = (
            cred_def_id,
            json.dumps(cred_def),
        )

        async with ledger:
            ledger.pool_handle.submit_request.side_effect = (
                {
                    "seqNo": 99,
                    "dest": "55GkHamhTU1ZbTbV2ab9DE",
                    "data": {
                        "name": "schema_name",
                        "version": "9.1",
                        "attr_names": ["a", "b"],
                    },
                },
                {"data": None},  # cred def lookup result
                {},  # submission result
            )

            result = await ledger.create_and_send_credential_definition(
                issuer=issuer,
                schema_id=schema_id,
                signature_type="CL",
                tag="tag",
                support_revocation=False,
            )
            assert result == (cred_def_id, cred_def, True)

    @pytest.mark.asyncio
    async def test_send_credential_definition_no_public_did(
        self,
        ledger: IndyVdrLedger,
    ):
        issuer = async_mock.MagicMock(IndyIssuer)
        async with ledger:
            with pytest.raises(BadLedgerRequestError):
                await ledger.create_and_send_credential_definition(
                    issuer, "schema_id", None, "tag"
                )

    @pytest.mark.asyncio
    async def test_send_credential_definition_no_such_schema(
        self, ledger: IndyVdrLedger
    ):
        issuer = async_mock.MagicMock(IndyIssuer)
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {}
            with pytest.raises(BadLedgerRequestError):
                await ledger.create_and_send_credential_definition(
                    issuer, "schema_id", None, "tag"
                )

    @pytest.mark.asyncio
    async def test_send_credential_definition_read_only(self, ledger: IndyVdrLedger):
        issuer = async_mock.MagicMock(IndyIssuer)
        async with ledger:
            ledger.pool.read_only = True
            with pytest.raises(LedgerError):
                await ledger.create_and_send_credential_definition(
                    issuer, "schema_id", None, "tag"
                )

    @pytest.mark.asyncio
    async def test_get_credential_definition(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "seqNo": 99,
                "ref": "schema-id",
                "signature_type": "CL",
                "tag": "tag",
                "origin": "origin-did",
                "data": {"cred": "def"},
            }

            result = await ledger.get_credential_definition(
                "55GkHamhTU1ZbTbV2ab9DE:3:CL:99:tag"
            )
            assert result == {
                "ver": "1.0",
                "id": "origin-did:3:CL:schema-id:tag",
                "schemaId": "schema-id",
                "type": "CL",
                "tag": "tag",
                "value": {"cred": "def"},
            }

    @pytest.mark.asyncio
    async def test_get_credential_definition_not_found(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "seqNo": 99,
                "ref": "schema-id",
                "signature_type": "CL",
                "tag": "tag",
                "origin": "origin-did",
                "data": None,
            }

            result = await ledger.get_credential_definition(
                "55GkHamhTU1ZbTbV2ab9DE:3:CL:99:tag"
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_get_key_for_did(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "data": r'{"verkey": "VK"}',
            }
            result = await ledger.get_key_for_did("55GkHamhTU1ZbTbV2ab9DE")
            assert result == "VK"

    @pytest.mark.asyncio
    async def test_get_all_endpoints_for_did(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "data": r'{"endpoint": {"default": "endp"}}',
            }
            result = await ledger.get_all_endpoints_for_did("55GkHamhTU1ZbTbV2ab9DE")
            assert result == {"default": "endp"}

    @pytest.mark.asyncio
    async def test_get_all_endpoints_for_did_none(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "data": None,
            }
            result = await ledger.get_all_endpoints_for_did("55GkHamhTU1ZbTbV2ab9DE")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_endpoint_for_did(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "data": r'{"endpoint": {"endpoint": "endp"}}',
            }
            result = await ledger.get_endpoint_for_did(
                "55GkHamhTU1ZbTbV2ab9DE", EndpointType.ENDPOINT
            )
            assert result == "endp"

    @pytest.mark.asyncio
    async def test_get_endpoint_for_did_address_none(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "data": r'{"endpoint": null}',
            }
            result = await ledger.get_endpoint_for_did(
                "55GkHamhTU1ZbTbV2ab9DE", EndpointType.ENDPOINT
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_get_endpoint_for_did_empty(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "data": None,
            }
            result = await ledger.get_endpoint_for_did(
                "55GkHamhTU1ZbTbV2ab9DE", EndpointType.ENDPOINT
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_update_endpoint_for_did(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet = (await ledger.profile.session()).wallet
        test_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        async with ledger:
            ledger.pool_handle.submit_request.side_effect = (
                {"data": None},
                {"data": None},
            )
            result = await ledger.update_endpoint_for_did(
                "55GkHamhTU1ZbTbV2ab9DE", "https://url", EndpointType.ENDPOINT
            )

    @pytest.mark.parametrize(
        "all_exist_endpoints, routing_keys, result",
        [
            (
                {"Endpoint": "https://endpoint"},
                ["3YJCx3TqotDWFGv7JMR5erEvrmgu5y4FDqjR7sKWxgXn"],
                {
                    "endpoint": {
                        "Endpoint": "https://endpoint",
                        "endpoint": {
                            "endpoint": "https://url",
                            "routingKeys": [
                                "3YJCx3TqotDWFGv7JMR5erEvrmgu5y4FDqjR7sKWxgXn"
                            ],
                        },
                    }
                },
            ),
            (
                {"Endpoint": "https://endpoint"},
                None,
                {
                    "endpoint": {
                        "Endpoint": "https://endpoint",
                        "endpoint": {"endpoint": "https://url", "routingKeys": []},
                    }
                },
            ),
            (
                None,
                ["3YJCx3TqotDWFGv7JMR5erEvrmgu5y4FDqjR7sKWxgXn"],
                {
                    "endpoint": {
                        "endpoint": {
                            "endpoint": "https://url",
                            "routingKeys": [
                                "3YJCx3TqotDWFGv7JMR5erEvrmgu5y4FDqjR7sKWxgXn"
                            ],
                        }
                    }
                },
            ),
            (
                None,
                None,
                {
                    "endpoint": {
                        "endpoint": {"endpoint": "https://url", "routingKeys": []}
                    }
                },
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_construct_attr_json(
        self, ledger: IndyVdrLedger, all_exist_endpoints, routing_keys, result
    ):
        async with ledger:
            attr_json = await ledger._construct_attr_json(
                "https://url", EndpointType.ENDPOINT, all_exist_endpoints, routing_keys
            )
        assert attr_json == json.dumps(result)

    @pytest.mark.asyncio
    async def test_update_endpoint_for_did_calls_attr_json(self, ledger: IndyVdrLedger):
        routing_keys = ["3YJCx3TqotDWFGv7JMR5erEvrmgu5y4FDqjR7sKWxgXn"]
        wallet = (await ledger.profile.session()).wallet
        test_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)

        async with ledger:
            with async_mock.patch.object(
                ledger,
                "_construct_attr_json",
                async_mock.CoroutineMock(
                    return_value=json.dumps(
                        {
                            "endpoint": {
                                "endpoint": {
                                    "endpoint": "https://url",
                                    "routingKeys": [],
                                }
                            }
                        }
                    )
                ),
            ) as mock_construct_attr_json, async_mock.patch.object(
                ledger,
                "get_all_endpoints_for_did",
                async_mock.CoroutineMock(return_value={}),
            ):
                await ledger.update_endpoint_for_did(
                    test_did.did,
                    "https://url",
                    EndpointType.ENDPOINT,
                    routing_keys=routing_keys,
                )
                mock_construct_attr_json.assert_called_once_with(
                    "https://url",
                    EndpointType.ENDPOINT,
                    {},
                    routing_keys,
                )

    @pytest.mark.asyncio
    async def test_update_endpoint_for_did_no_public(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {"data": None}
            with pytest.raises(BadLedgerRequestError):
                await ledger.update_endpoint_for_did(
                    "55GkHamhTU1ZbTbV2ab9DE", "https://url", EndpointType.ENDPOINT
                )

    @pytest.mark.asyncio
    async def test_update_endpoint_for_did_read_only(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool.read_only = True
            ledger.pool_handle.submit_request.return_value = {"data": None}
            with pytest.raises(LedgerError):
                await ledger.update_endpoint_for_did(
                    "55GkHamhTU1ZbTbV2ab9DE", "https://url", EndpointType.ENDPOINT
                )

    @pytest.mark.asyncio
    async def test_register_nym_local(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet: BaseWallet = (await ledger.profile.session()).wallet
        public_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        post_did = await wallet.create_local_did(DIDMethod.SOV, KeyType.ED25519)
        async with ledger:
            await ledger.register_nym(post_did.did, post_did.verkey)
        did = await wallet.get_local_did(post_did.did)
        assert did.metadata["posted"] == True

    @pytest.mark.asyncio
    async def test_register_nym_non_local(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet: BaseWallet = (await ledger.profile.session()).wallet
        public_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        async with ledger:
            await ledger.register_nym("55GkHamhTU1ZbTbV2ab9DE", "verkey")

    @pytest.mark.asyncio
    async def test_register_nym_no_public(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            with pytest.raises(BadLedgerRequestError):
                await ledger.register_nym("55GkHamhTU1ZbTbV2ab9DE", "verkey")

    @pytest.mark.asyncio
    async def test_register_nym_read_only(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool.read_only = True
            with pytest.raises(LedgerError):
                await ledger.register_nym(
                    "55GkHamhTU1ZbTbV2ab9DE",
                    "verkey",
                    "",
                )

    @pytest.mark.asyncio
    async def test_get_nym_role(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "data": r'{"role":"TRUSTEE"}'
            }
            result = await ledger.get_nym_role(
                "55GkHamhTU1ZbTbV2ab9DE",
            )
            assert result == Role.TRUSTEE

    @pytest.mark.asyncio
    async def test_get_nym_role_unknown(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {"data": r"{}"}
            with pytest.raises(BadLedgerRequestError):
                await ledger.get_nym_role(
                    "55GkHamhTU1ZbTbV2ab9DE",
                )

    @pytest.mark.asyncio
    async def test_get_nym_role_invalid(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            ledger.pool_handle.submit_request.return_value = {
                "data": r'{"role":"INVALID"}'
            }
            result = await ledger.get_nym_role(
                "55GkHamhTU1ZbTbV2ab9DE",
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_get_revoc_reg_def(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            reg_id = (
                "55GkHamhTU1ZbTbV2ab9DE:4:55GkHamhTU1ZbTbV2ab9DE:3:CL:99:tag:CL_ACCUM:0"
            )
            ledger.pool_handle.submit_request.return_value = {
                "data": {"id": reg_id},
                "txnTime": 1234567890,
            }
            result = await ledger.get_revoc_reg_def(
                reg_id,
            )
            assert result["id"] == reg_id
            assert result["txnTime"] == 1234567890

    @pytest.mark.asyncio
    async def test_get_revoc_reg_entry(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            reg_id = (
                "55GkHamhTU1ZbTbV2ab9DE:4:55GkHamhTU1ZbTbV2ab9DE:3:CL:99:tag:CL_ACCUM:0"
            )
            ledger.pool_handle.submit_request.return_value = {
                "data": {
                    "id": reg_id,
                    "txnTime": 1234567890,
                    "value": "...",
                    "revocRegDefId": reg_id,
                },
            }
            result = await ledger.get_revoc_reg_entry(reg_id, 1234567890)
            assert result == ({"ver": "1.0", "value": "..."}, 1234567890)

    @pytest.mark.asyncio
    async def test_get_revoc_reg_delta(
        self,
        ledger: IndyVdrLedger,
    ):
        async with ledger:
            reg_id = (
                "55GkHamhTU1ZbTbV2ab9DE:4:55GkHamhTU1ZbTbV2ab9DE:3:CL:99:tag:CL_ACCUM:0"
            )
            ledger.pool_handle.submit_request.return_value = {
                "data": {
                    "value": {
                        "accum_to": {
                            "value": {"accum": "ACCUM"},
                            "txnTime": 1234567890,
                        },
                        "issued": [1, 2],
                        "revoked": [3, 4],
                    },
                    "revocRegDefId": reg_id,
                },
            }
            result = await ledger.get_revoc_reg_delta(reg_id)
            assert result == (
                {
                    "ver": "1.0",
                    "value": {"accum": "ACCUM", "issued": [1, 2], "revoked": [3, 4]},
                },
                1234567890,
            )

    @pytest.mark.asyncio
    async def test_send_revoc_reg_def(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet: BaseWallet = (await ledger.profile.session()).wallet
        public_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        async with ledger:
            reg_id = (
                "55GkHamhTU1ZbTbV2ab9DE:4:55GkHamhTU1ZbTbV2ab9DE:3:CL:99:tag:CL_ACCUM:0"
            )
            reg_def = {
                "ver": "1.0",
                "id": reg_id,
                "revocDefType": "CL_ACCUM",
                "tag": "tag1",
                "credDefId": "55GkHamhTU1ZbTbV2ab9DE:3:CL:99:tag",
                "value": {
                    "issuanceType": "ISSUANCE_ON_DEMAND",
                    "maxCredNum": 5,
                    "publicKeys": {"accumKey": {"z": "1 ..."}},
                    "tailsHash": "",
                    "tailsLocation": "",
                },
            }
            ledger.pool_handle.submit_request.return_value = {"status": "ok"}
            result = await ledger.send_revoc_reg_def(reg_def, issuer_did=None)
            assert result == {"result": {"status": "ok"}}

    @pytest.mark.asyncio
    async def test_send_revoc_reg_entry(
        self,
        ledger: IndyVdrLedger,
    ):
        wallet: BaseWallet = (await ledger.profile.session()).wallet
        public_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)
        async with ledger:
            reg_id = (
                "55GkHamhTU1ZbTbV2ab9DE:4:55GkHamhTU1ZbTbV2ab9DE:3:CL:99:tag:CL_ACCUM:0"
            )
            reg_entry = {
                "ver": "1.0",
                "value": {},
            }
            ledger.pool_handle.submit_request.return_value = {"status": "ok"}
            result = await ledger.send_revoc_reg_entry(reg_id, "CL_ACCUM", reg_entry)
            assert result == {"result": {"status": "ok"}}

    @pytest.mark.asyncio
    async def test_credential_definition_id2schema_id(self, ledger: IndyVdrLedger):
        S_ID = f"55GkHamhTU1ZbTbV2ab9DE:2:favourite_drink:1.0"
        SEQ_NO = "9999"

        async with ledger:
            with async_mock.patch.object(
                ledger,
                "get_schema",
                async_mock.CoroutineMock(return_value={"id": S_ID}),
            ) as mock_get_schema:
                s_id_short = await ledger.credential_definition_id2schema_id(
                    f"55GkHamhTU1ZbTbV2ab9DE:3:CL:{SEQ_NO}:tag"
                )

                mock_get_schema.assert_called_once_with(SEQ_NO)

                assert s_id_short == S_ID
                s_id_long = await ledger.credential_definition_id2schema_id(
                    f"55GkHamhTU1ZbTbV2ab9DE:3:CL:{s_id_short}:tag"
                )
                assert s_id_long == s_id_short

    @pytest.mark.asyncio
    async def test_rotate_did_keypair(self, ledger: IndyVdrLedger):
        wallet = (await ledger.profile.session()).wallet
        public_did = await wallet.create_public_did(DIDMethod.SOV, KeyType.ED25519)

        async with ledger:
            with async_mock.patch.object(
                ledger.pool_handle,
                "submit_request",
                async_mock.CoroutineMock(
                    side_effect=[
                        {"data": json.dumps({"seqNo": 1234})},
                        {"data": {"txn": {"data": {"role": "101", "alias": "Billy"}}}},
                        {"data": "ok"},
                    ]
                ),
            ):
                await ledger.rotate_public_did_keypair()
