#!/usr/bin/env python3
"""Generate the connector's placeholder icons.

info.json names small_icon.png and large_icon.png, and the packaging rules let a
package install while naming icons it does not ship -- which means a missing
icon shows up as a blank tile in Content Hub rather than as an install failure.
So they are generated here rather than left to chance.

Deliberately dependency-free: Pillow is not in the connector's requirements and
adding it just to draw two squares would ship an image library to every
appliance running this connector. A PNG is a zlib-compressed scanline stream, so
stdlib covers it.

    python3 tools/make_icons.py
"""

import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IMAGE_DIR = os.path.join(ROOT, 'ninjaone', 'images')

BACKGROUND = (20, 26, 46)     # deep navy
FOREGROUND = (108, 196, 255)  # light blue


def glyph_n(x, y, size):
    """True where pixel (x, y) falls inside a letter 'N'."""
    unit = size / 16.0
    left, right = 4 * unit, 12 * unit
    top, bottom = 4 * unit, 12 * unit
    stroke = 1.7 * unit

    if not (top <= y <= bottom):
        return False
    # The two uprights.
    if left <= x <= left + stroke or right - stroke <= x <= right:
        return True
    # The diagonal, as a band around the line from top-left to bottom-right.
    span = right - left
    if span <= 0:
        return False
    expected = left + (y - top) / (bottom - top) * span
    return abs(x - expected) <= stroke * 0.78


def render(size):
    rows = []
    for y in range(size):
        row = bytearray([0])  # filter byte 0 (None) per scanline
        for x in range(size):
            inside = glyph_n(x + 0.5, y + 0.5, size)
            row.extend(FOREGROUND if inside else BACKGROUND)
        rows.append(bytes(row))
    return b''.join(rows)


def chunk(tag, payload):
    return (struct.pack('>I', len(payload)) + tag + payload
            + struct.pack('>I', zlib.crc32(tag + payload) & 0xFFFFFFFF))


def write_png(path, size):
    header = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)  # 8-bit RGB
    data = (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', header)
            + chunk(b'IDAT', zlib.compress(render(size), 9))
            + chunk(b'IEND', b''))
    with open(path, 'wb') as handle:
        handle.write(data)
    return len(data)


def main():
    os.makedirs(IMAGE_DIR, exist_ok=True)
    for name, size in (('small_icon.png', 150), ('large_icon.png', 500)):
        path = os.path.join(IMAGE_DIR, name)
        written = write_png(path, size)
        print(f'wrote {path} ({size}x{size}, {written} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
