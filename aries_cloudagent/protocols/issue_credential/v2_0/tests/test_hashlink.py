from ..hashlink import Hashlink

EXAMPLE_DATA = b"Hello World!"
EXAMPLE_LINK = "hl:zQmWvQxTqbG2Z9HPJgG57jjwR154cKhbtJenbyYTWkjgF3e:zuh8iaLobXC8g9tfma1CSTtYBakXeSTkHrYA5hmD4F7dCLw8XYwZ1GWyJ3zwF"
EXAMPLE_DATA_SHA = bytes.fromhex(
    "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
)


def test_example_link():
    hashlink = Hashlink(
        "sha2-256",
        "base58btc",
        EXAMPLE_DATA,
        {"url": ["http://example.org/hw.txt"], "content-type": "text/plain"},
    )
    assert hashlink.link == EXAMPLE_LINK


def test_serialize_metadata():
    hashlink = Hashlink(
        "sha2-256",
        "base58btc",
        EXAMPLE_DATA,
        {"url": ["http://example.org/hw.txt"], "content-type": "text/plain"},
    )

    assert hashlink._serialize_metadata() == EXAMPLE_LINK.split(":")[2]


def test_deserialize_data():

    data = EXAMPLE_LINK.split(":")[1]

    assert Hashlink._deserialize_data(data) == EXAMPLE_DATA_SHA


def test_verify_link():

    assert Hashlink.verify(EXAMPLE_LINK, EXAMPLE_DATA)
    assert Hashlink.verify(EXAMPLE_LINK, b"Bad Data!") == False
    assert Hashlink.verify(EXAMPLE_LINK) == False
