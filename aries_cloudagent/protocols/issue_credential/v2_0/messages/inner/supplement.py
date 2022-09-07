"""Supplements inner model."""

from typing import Optional, Sequence
from uuid import uuid4
from marshmallow import fields, validate

from aries_cloudagent.messaging.valid import UUID4
from ......messaging.models.base import BaseModel, BaseModelSchema


class SupplementAttribute(BaseModel):
    """Supplement Attribute model."""

    class Meta:
        """Supplement Attribute meta."""

        schema_class = "SupplementAttributeSchema"

    def __init__(self, key: str, value: str, **kwargs):
        """Initialize suppplement attribute."""
        super().__init__(**kwargs)
        self.key = key
        self.value = value


class SupplementAttributeSchema(BaseModelSchema):
    """Supplement attribute schema."""

    class Meta:
        """Supplement attribute meta."""

        model_class = SupplementAttribute

    key = fields.Str(description="Key of attribute key value pair", required=True)
    value = fields.Str(description="Value of attribute key value pair", required=True)


class Supplement(BaseModel):
    """Model for the supplements received in issue credential message."""

    class Meta:
        """Meta of Supplements."""

        schema_class = "SupplementSchema"

    def __init__(
        self,
        *,
        type: str,
        ref: str,
        attrs: Sequence[SupplementAttribute],
        id: Optional[str] = None,
        **kwargs
    ):
        """Initialize supplements."""
        super().__init__(**kwargs)
        self.type = type
        self.id = id or str(uuid4())
        self.ref = ref
        self.attrs = attrs


class SupplementSchema(BaseModelSchema):
    """Supplements schema."""

    class Meta:
        """Supplements meta."""

        model_class = Supplement

    type = fields.Str(
        description="Type of the supplement",
        required=True,
        validate=validate.OneOf(["hashlink-data", "issuer-credential"]),
    )

    id = fields.Str(description="Unique ID for the supplement", required=False, **UUID4)

    ref = fields.Str(
        description="Reference to ID of attachment described by this supplement",
        required=True,
        **UUID4
    )

    attrs = fields.Nested(
        SupplementAttributeSchema,
        many=True,
        required=False,
        description="Additional information for supplement",
    )
