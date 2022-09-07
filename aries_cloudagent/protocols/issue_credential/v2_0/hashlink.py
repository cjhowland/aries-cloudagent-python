"""Hashlink helper class."""

from enum import Enum
from typing import Any, Dict, Optional
from hashlib import sha256

import cbor2
from cbor2.decoder import CBORDecoder
from cbor2.encoder import CBOREncoder
from cbor2.types import CBORTag


# TODO replace with hashberg-io/multiformats after python 3.7 upgrade
import multibase


class HashAlg(Enum):
    """Supported hash algorithms for hashlinks."""

    SHA256 = ""
    SHA512 = ""


def _cbor_uri_encoder(encoder: CBOREncoder, value: Any):
    if isinstance(value, CBORTag):
        encoder.encode_length(6, value.tag)
        encoder.encode(value.value)


def _cbor_uri_decoder(decoder: CBORDecoder, tag: CBORTag):
    if tag.tag == 32:
        return tag.value
    return tag


class Hashlink:
    """Hashlink object.

    Used to help produce and verify hashlinks.
    """

    SCHEME = "hl"
    SEPARATOR = ":"

    def __init__(
        self, alg: str, enc: str, data: bytes, metadata: Optional[Dict[str, Any]] = None
    ):
        """Initialize this hashlink."""
        if alg != "sha2-256":
            raise ValueError("Only sha2-256 supported for now")

        self.alg = alg
        self.enc = enc
        self.metadata = metadata
        self.data = data
        self._link: Optional[str] = None

    def __str__(self):
        """Get string representation of hashlink."""
        return self.link

    @property
    def link(self):
        """Get link."""
        if not self._link:
            prefix = self.SCHEME + self.SEPARATOR
            resource_hash = multibase.encode(
                # TODO replace with multiformats.multihash
                self.enc,
                b"\x12\x20" + sha256(self.data).digest(),
            ).decode()
            link = f"{prefix}{resource_hash}"
            if self.metadata:
                metadata = self._serialize_metadata()
                link = f"{link}{self.SEPARATOR}{metadata}"

            self._link = link
        return self._link

    def _serialize_metadata(self) -> Optional[str]:
        """Serialize the metadata according to IETF RFC on cryptographic hashlinks.

        URL: https://datatracker.ietf.org/doc/html/draft-sporny-hashlink-07

        To generate the value for the metadata, the metadata values are
        encoded in the CBOR Data Format [RFC7049] using the following
        algorithm:

        1.  Create the raw output map (CBOR major type 5).

        2.  If at least one URL exists, add a CBOR key of 15 (0x0f) to the
            raw output map with a value that is an array (CBOR major type 4).

            1.  Encode each URL as a CBOR URI (CBOR type 32;
            https://www.rfc-editor.org/rfc/rfc8949.html#encodedtext) and place
            it into the array.

        3.  If the content type exists, add a CBOR key of 14 (0x0e) to the
            raw output map with a value that is a UTF-8 byte string (0x6) and
            the value of the content type.

        4.  If experimental metadata exists, add a CBOR key of 13 (0x0d) and
            encode it as a map by creating a raw output map (CBOR major type
            5).  For each item in the map, serialize to CBOR where the CBOR
            major types, the key name, and the value is derived from the
            input data.  For example a key of "foo" and a value of 200 would
            be encoded as a CBOR major type of 2 for the key and a CBOR major
            type of 0 for the value.

        5.  Generate the multibase value by encoding the raw output map using
            the Multibase Data Format.

        The example below demonstrates the output of the algorithm above for
        metadata containing a single URL ("http://example.org/hw.txt") with a
        content type of "text/plain" expressed using the base-58 Bitcoin
        base-encoding format:

        zuh8iaLobXC8g9tfma1CSTtYBakXeSTkHrYA5hmD4F7dCLw8XYwZ1GWyJ3zwF

        Example metadata dictionary:
        {
            "url": ["https://example.com"],
            "content-type": "application/json",
            "experimental": { ... },
        }
        """
        if not self.metadata:
            return None

        output = {}

        if "url" in self.metadata:
            output[15] = [CBORTag(32, url) for url in self.metadata["url"]]

        if "content-type" in self.metadata:
            output[14] = self.metadata["content-type"]

        if "experimental" in self.metadata:
            output[13] = self.metadata["experimental"]

        return multibase.encode(
            self.enc, cbor2.dumps(output, default=_cbor_uri_encoder)
        ).decode()

    @classmethod
    def _deserialize_metadata(cls, metadata: str) -> Dict[str, Any]:
        """Deserialize the haslink metadata.

        To deserialize the metadata, the "Serializing the Metadata" algorithm
        is reversed.  Implementers MUST use the following table to
        deserialize keys to JSON:


                  +-----------+----------------+------------------+
                  | Key (hex) |    JSON key    |    JSON value    |
                  +-----------+----------------+------------------+
                  |    0x0f   |     "url"      | Array of strings |
                  |    0x0e   | "content-type" |      string      |
                  |    0x0d   | "experimental" |   JSON Object    |
                  +-----------+----------------+------------------+

                       Table 1: Multihash Algorithms Registry

        The example below demonstrates the output of the algorithm above for
        metadata containing a single URL ("http://example.org/hw.txt") with a
        content type of "text/plain", and an experimental metadata key of
        "foo" and value of 123:

        {
          "url": ["http://example.org/hw.txt"],
          "content-type": "text/plain",
          "experimental": {
            "foo": 123
          }
        }
        """
        raw = cbor2.loads(multibase.decode(metadata), tag_hook=_cbor_uri_decoder)
        deserialized = {}
        if 15 in raw:
            deserialized["url"] = raw[15]

        if 14 in raw:
            deserialized["content-type"] = raw[14]

        if 13 in raw:
            deserialized["experimental"] = raw[13]

        return deserialized

    @classmethod
    def _deserialize_data(cls, data: bytes) -> bytes:
        """
        Deserialize the data portion of a hashlink.

        Parameters:
            data -> The data portion of the hashlink
        Returns:
            bytes -> The decoded hash of the hashlink data
        """
        raw = multibase.decode(data)
        header = raw[:2]
        raw_hash = raw[2:]

        # Currently only SHA2-256 is supported
        if header[0] != 0x12:
            raise Exception("Unknown hash algorithm used: {}".format(header[0]))

        length = header[1]
        if length != len(raw_hash):
            raise Exception("hash length doesn't match length header")

        return raw_hash

    @classmethod
    def verify(
        cls, link: str, data: Optional[bytes] = None, *, check_remote: bool = False
    ) -> bool:
        """Verify the hash of the data linked to by the hashlink."""

        link_split = link.split(cls.SEPARATOR)

        if link_split[0] != cls.SCHEME:
            return False

        link_data_hash = cls._deserialize_data(link_split[1])

        # TODO add check for when check_remote is true
        if not check_remote:
            if data is None:
                data = b""
            data_hash = sha256(data).digest()

            if link_data_hash == data_hash:
                return True

        return False
