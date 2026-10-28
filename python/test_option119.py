import unittest

from option119 import (
    Option119Error,
    decode,
    encode,
    from_cstring,
    from_hex,
    from_mikrotik,
    split_input,
    to_cisco,
    to_cstring,
    to_hex,
    to_mikrotik,
)


def explode(parts):
    result = []
    for part in parts:
        result.extend(part if isinstance(part, str) else [part])
    return result


class EncodeTests(unittest.TestCase):
    def test_encodes_domains_and_back_pointers(self):
        self.assertEqual(encode(["google.com"]), explode([6, "google", 3, "com", 0]))
        self.assertEqual(
            encode(["mydomain.home", "users.mydomain.home", "remote.users.mydomain.home"]),
            explode([8, "mydomain", 4, "home", 0, 5, "users", 192, 0, 6, "remote", 192, 15]),
        )
        self.assertEqual(
            encode(["services.myhome.me", "devices.myhome.me", "myhome.me", "something-else.com"]),
            explode([8, "services", 6, "myhome", 2, "me", 0, 7, "devices", 192, 9, 192, 9, 14, "something-else", 3, "com", 0]),
        )

    def test_handles_trailing_dots_and_whitespace(self):
        self.assertEqual(split_input("  Google.com   yahoo.com "), ["google.com", "yahoo.com"])
        self.assertEqual(encode(["google.com.", "yahoo.com"]), explode([6, "google", 3, "com", 0, 5, "yahoo", 192, 7]))

    def test_output_formats(self):
        encoded = encode(["google.com", "yahoo.com"])
        self.assertEqual(to_mikrotik(encoded), "0x06'google'0x03'com'0x0005'yahoo'0xC007")
        self.assertEqual(to_hex(encoded), "06676F6F676C6503636F6D00057961686F6FC007")
        self.assertEqual(to_cisco(encoded)[:14], "0667.6F6F.676C")
        self.assertEqual(to_cstring(encoded), "\\x06google\\x03com\\x00\\x05yahoo\\xC0\\x07")
        self.assertEqual(to_mikrotik(encode(["555.google.com"])), "0x03s'555'0x06'google'0x03'com'0x00")

    def test_rejects_invalid_domains(self):
        for domains in (["google.com.."], ["bad..example"], ["a" * 64 + ".com"], ["exämple.com"]):
            with self.assertRaises(Option119Error):
                encode(domains)


class DecodeTests(unittest.TestCase):
    cases = [
        "google.com telegraph.co.uk",
        "mydomain.home users.mydomain.home remote.users.mydomain.home",
        "remote.users.mydomain.home users.mydomain.home mydomain.home",
        "services.myhome.me devices.myhome.me myhome.me something-else.com",
        "google.com 0.google.com 555.yahoo.com",
    ]

    def test_round_trips_all_formats(self):
        for case in self.cases:
            encoded = encode(split_input(case))
            self.assertEqual(decode(from_hex(to_hex(encoded))), case)
            self.assertEqual(decode(from_hex(to_cisco(encoded))), case)
            self.assertEqual(decode(from_mikrotik(to_mikrotik(encoded))), case)
            self.assertEqual(decode(from_cstring(to_cstring(encoded))), case)

    def test_mikrotik_literals(self):
        self.assertEqual(decode(from_mikrotik("0x02s'65'0x06'google'0x03'com'0x00")), "65.google.com")
        self.assertEqual(decode(from_mikrotik("0x01'65'0x06'google'0x03'com'0x00")), "A.google.com")
        self.assertEqual(decode(from_mikrotik("0x06'google'0x03'com'0x000579'97.104.111.111'0xC007")), "google.com yahoo.com")

    def test_cstring_octal_escapes(self):
        self.assertEqual(decode(from_cstring("\\003com\\000")), "com")

    def test_rejects_bad_inputs(self):
        for data in (
            [3, 99, 111, 109, 192, 0, 0],
            [4, 116, 101, 115, 116, 192, 7, 3, 99, 111, 109, 0],
            [4, 116, 101, 115, 116, 3, 99, 111, 109],
            [3, 65, 66, 67, 4, 65, 66, 67],
        ):
            with self.assertRaises(Option119Error):
                decode(data)
        for value in ("0", "000", "   00 00 0 00", ".00.0.00"):
            with self.assertRaises(Option119Error):
                from_hex(value)


if __name__ == "__main__":
    unittest.main()
