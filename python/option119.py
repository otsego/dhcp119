#!/usr/bin/env python3
# option119.py - DHCP Option 119 encoder/decoder for Linux and macOS
# Copyright (C) 2020 John J. Jordan
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Encode and decode DHCP Option 119 (domain search list) values."""

import argparse
import re
import sys

FORMATS = ("mikrotik", "cisco", "hex", "spaced-hex", "systemd")


class Option119Error(ValueError):
    pass


def split_input(value):
    if isinstance(value, str):
        value = [value]
    return [part for item in value for part in re.split(r"[\s,]+", item.lower()) if part]


def encode(domains):
    """Return a list of byte ints and one-character label strings."""
    refs = {}
    result = []

    for domain in domains:
        domain = domain.lower()
        if not domain.isascii():
            raise Option119Error("Domain names must be ASCII; use punycode for IDNs")
        if domain.endswith(".."):
            raise Option119Error("Domain cannot end with multiple periods")
        if domain.endswith("."):
            domain = domain[:-1]
        if not domain:
            raise Option119Error("Empty domain")

        branched = False
        t = 0
        while t < len(domain):
            subdomain = domain[t:]
            if subdomain in refs:
                ptr = 0xC000 | refs[subdomain]
                result.extend(((ptr >> 8) & 0xFF, ptr & 0xFF))
                branched = True
                break

            if len(result) <= 0x3FFF:
                refs[subdomain] = len(result)

            dot = domain.find(".", t)
            if dot < 0:
                dot = len(domain)
            if dot == t:
                raise Option119Error("Empty segment")
            if dot - t > 63:
                raise Option119Error("Domain label cannot exceed 63 characters")

            result.append(dot - t)
            result.extend(domain[t:dot])
            t = dot + 1

        if not branched:
            result.append(0)

    return result


def _octet(value):
    return ord(value) if isinstance(value, str) else value


def _hex(value):
    return f"{_octet(value):02X}"


def to_mikrotik(encoded):
    result = []
    i = 0
    while i < len(encoded):
        if isinstance(encoded[i], int):
            result.append("0x")
            while i < len(encoded) and isinstance(encoded[i], int):
                result.append(_hex(encoded[i]))
                i += 1
        else:
            start = i
            while i < len(encoded) and isinstance(encoded[i], str):
                i += 1
            segment = "".join(encoded[start:i])
            result.append(("s" if re.fullmatch(r"[0-9]+", segment) else "") + f"'{segment}'")
    return "".join(result)


def to_hex(encoded, sep=""):
    return sep.join(_hex(value) for value in encoded)


def to_cisco(encoded):
    return "".join(("." if i and i % 2 == 0 else "") + _hex(value) for i, value in enumerate(encoded))


def to_cstring(encoded):
    return "".join(value if isinstance(value, str) else f"\\x{value:02X}" for value in encoded)


def encode_formats(domains):
    encoded = encode(domains)
    return {
        "mikrotik": to_mikrotik(encoded),
        "cisco": to_cisco(encoded),
        "hex": to_hex(encoded),
        "spaced-hex": to_hex(encoded, " "),
        "systemd": to_cstring(encoded),
    }


def decode_segment(data, idx):
    value = data[idx]
    if value == 0:
        return {"kind": "end", "next": idx + 1}
    if value & 0xC0 == 0xC0:
        if idx + 1 >= len(data):
            raise Option119Error("Pointer extends beyond end of input")
        return {"kind": "ptr", "next": idx + 2, "ptr": ((value & 0x3F) << 8) | data[idx + 1]}
    if value & 0xC0:
        raise Option119Error("Bad start byte")
    if idx + value >= len(data):
        raise Option119Error("Segment extends beyond end of input")
    return {"kind": "text", "next": idx + value + 1, "text": bytes(data[idx + 1 : idx + value + 1]).decode("latin-1")}


def read_name(data, idx):
    labels = []
    i = idx
    while i < len(data):
        segment = decode_segment(data, i)
        if segment["kind"] == "end":
            return ".".join(labels), segment["next"]
        if segment["kind"] == "text":
            labels.append(segment["text"])
            i = segment["next"]
            continue
        if segment["ptr"] >= idx:
            raise Option119Error("Invalid forward or circular reference")
        labels.append(read_name(data, segment["ptr"])[0])
        return ".".join(labels), segment["next"]
    raise Option119Error("Missing END marker")


def decode(data):
    names = []
    i = 0
    while i < len(data):
        name, i = read_name(data, i)
        names.append(name)
    return " ".join(names)


def _is_hex(value):
    return bool(value) and all(char in "0123456789abcdefABCDEF" for char in value)


def from_hex(value):
    result = []
    i = 0
    while i < len(value):
        if value[i] in " .;:\t\r\n":
            i += 1
            continue
        if i == len(value) - 1:
            raise Option119Error("Need an even number of hex digits")
        octet = value[i : i + 2]
        if not _is_hex(octet):
            raise Option119Error("Unexpected hex character")
        result.append(int(octet, 16))
        i += 2
    return result


def from_mikrotik(value):
    result = []
    i = 0
    while i < len(value):
        if value[i].isspace():
            i += 1
        elif value[i : i + 2].lower() == "s'":
            end = value.find("'", i + 2)
            if end < 0:
                raise Option119Error("Unterminated string")
            result.extend(ord(char) for char in value[i + 2 : end])
            i = end + 1
        elif value[i] == "'":
            end = value.find("'", i + 1)
            if end < 0:
                raise Option119Error("Unterminated string")
            contents = value[i + 1 : end]
            if re.fullmatch(r"[0-9]+", contents):
                number = int(contents, 10)
                if number > 255:
                    raise Option119Error("Numeric literal must be between 0 and 255")
                result.append(number)
            elif re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", contents):
                octets = [int(part, 10) for part in contents.split(".")]
                if any(octet > 255 for octet in octets):
                    raise Option119Error("Invalid IP address literal")
                result.extend(octets)
            else:
                result.extend(ord(char) for char in contents)
            i = end + 1
        elif value[i : i + 2].lower() == "0x":
            i += 2
            start = i
            while i + 1 < len(value) and _is_hex(value[i : i + 2]):
                result.append(int(value[i : i + 2], 16))
                i += 2
            if i == start or (i < len(value) and _is_hex(value[i])):
                raise Option119Error("Invalid hex sequence")
        else:
            raise Option119Error("Unexpected input")
    return result


def from_cstring(value):
    result = []
    i = 0
    while i < len(value):
        if value[i] != "\\":
            result.append(ord(value[i]))
            i += 1
            continue
        if value[i + 1 : i + 2] == "x":
            octet = value[i + 2 : i + 4]
            if len(octet) != 2 or not _is_hex(octet):
                raise Option119Error("Invalid hex escape in C string")
            result.append(int(octet, 16))
            i += 4
            continue
        match = re.match(r"[0-7]{1,3}", value[i + 1 :])
        if not match:
            raise Option119Error("Unsupported escape code in C string")
        number = int(match.group(0), 8)
        if number > 255:
            raise Option119Error("Octal escape must be between 0 and 377")
        result.append(number)
        i += len(match.group(0)) + 1
    return result


def parse_encoded(value):
    if "\\" in value:
        return from_cstring(value)
    if "0x" in value.lower() or "'" in value:
        return from_mikrotik(value)
    return from_hex(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Encode or decode DHCP Option 119 domain search lists.")
    commands = parser.add_subparsers(dest="command", required=True)

    encode_parser = commands.add_parser("encode", help="encode one or more domain names")
    encode_parser.add_argument("domains", nargs="+", help="domains, separated by spaces or commas")
    encode_parser.add_argument("-f", "--format", choices=("all",) + FORMATS, default="all")

    decode_parser = commands.add_parser("decode", help="decode hex, Cisco, Mikrotik, or systemd input")
    decode_parser.add_argument("value", nargs="?", help="encoded value; reads stdin when omitted")

    args = parser.parse_args(argv)
    try:
        if args.command == "encode":
            domains = split_input(args.domains)
            if not domains:
                raise Option119Error("Empty input")
            output = encode_formats(domains)
            if args.format == "all":
                for name in FORMATS:
                    print(f"{name}: {output[name]}")
            else:
                print(output[args.format])
        else:
            value = args.value if args.value is not None else sys.stdin.read()
            print(decode(parse_encoded(value.strip())))
    except Option119Error as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
