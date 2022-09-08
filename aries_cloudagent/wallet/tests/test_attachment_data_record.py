import pytest

from ...messaging.decorators.attach_decorator import AttachDecorator
from ...messaging.responder import BaseResponder, MockResponder
from ...protocols.issue_credential.v2_0.messages.inner.supplement import Supplement
from ...core.in_memory import InMemoryProfile
from ...core.event_bus import EventBus
from ..models.attachment_data_record import AttachmentDataRecord


@pytest.fixture
def create_supplement():
    def _create_supplement(num):
        return Supplement(
            type="hashlink_data",
            attrs=[{"key": "field", "value": "<fieldname>"}],
            ref=None,
            id="attachment_id_" + str(num),
        )

    return _create_supplement


@pytest.fixture
def create_attachment():
    def _create_attachment(num):
        return AttachDecorator(
            ident="attachment_id_" + str(num),
            description=None,
            filename=None,
            mime_type=None,
            lastmod_time=None,
            byte_count=None,
            data="data_" + str(num),
        )

    return _create_attachment


@pytest.fixture
def event_bus():
    """Event bus fixture."""
    yield EventBus()


@pytest.fixture
def mock_responder():
    """Mock responder fixture."""
    yield MockResponder()


@pytest.fixture
def profile(event_bus, mock_responder):
    """Profile fixture."""
    yield InMemoryProfile.test_profile(
        bind={EventBus: event_bus, BaseResponder: mock_responder}
    )


def test_attachment_lookup(create_attachment):

    attachments = [create_attachment(1), create_attachment(2)]
    record = AttachmentDataRecord(Supplement, attachments)
    result = record.attachment_lookup(attachments)

    assert type(result) == dict
    for ident, attach_decorator in result.items():
        assert type(attach_decorator) == AttachDecorator
        assert ident == attach_decorator.ident
    assert result["attachment_id_1"].data == "data_1"
    assert result["attachment_id_2"].data == "data_2"


def test_match_by_attachment_id(create_supplement, create_attachment):

    supplements = [create_supplement(1), create_supplement(2)]
    attachments = [create_attachment(1), create_attachment(2)]
    result = AttachmentDataRecord.match_by_attachment_id(
        supplements, attachments, cred_id="test_cred_id"
    )

    for record in result:
        assert type(record) == AttachmentDataRecord
        assert record.attachment_id == record.supplement.id
        assert record.attribute == "<fieldname>"


@pytest.mark.asyncio
async def test_save_attachments(create_supplement, create_attachment, profile):

    async with profile.session() as session:
        supplements = [create_supplement(1), create_supplement(2)]
        attachments = [create_attachment(1), create_attachment(2)]
        result = await AttachmentDataRecord.save_attachments(
            session, supplements, attachments, cred_id="test_cred_id"
        )

        assert type(result) == list
        assert len(result) == 2
