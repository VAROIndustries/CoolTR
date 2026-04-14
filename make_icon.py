"""
Generate cooltr.ico — minimalist flat neon cyberpunk network-path icon.
Run once: python make_icon.py
"""
from PIL import Image, ImageDraw
import math

BG       = (6,  10,  24, 255)   # deep navy
CYAN     = (0,  240, 200, 255)  # neon cyan  — hops + lines
CYAN_DIM = (0,  130, 100, 180)  # dimmer cyan for line segments
MAGENTA  = (255, 20, 170, 255)  # neon magenta — destination node


def make_frame(size):
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # ── background with rounded corners ──────────────────────────────────────
    radius = max(2, int(size * 0.14))
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=BG)

    # ── node positions (fractions of size) ───────────────────────────────────
    # A diagonal traceroute path: 5 hops, one slight detour on hop 2→3
    raw = [
        (0.12, 0.84),   # 0 — source (bottom-left)
        (0.30, 0.60),   # 1
        (0.50, 0.66),   # 2 — slight jog down (routing detour)
        (0.70, 0.36),   # 3
        (0.88, 0.14),   # 4 — destination (top-right)
    ]
    nodes = [(x * size, y * size) for x, y in raw]

    lw = max(1, size // 26)   # line width
    nr = max(2, size // 16)   # node radius

    # ── connecting lines ─────────────────────────────────────────────────────
    for i in range(len(nodes) - 1):
        draw.line([nodes[i], nodes[i + 1]], fill=CYAN_DIM, width=lw)

    # ── nodes ────────────────────────────────────────────────────────────────
    for i, (x, y) in enumerate(nodes):
        if i == 0:
            # Source: hollow ring (cyan outline)
            outer = nr + max(1, size // 40)
            draw.ellipse([x-outer, y-outer, x+outer, y+outer], fill=CYAN)
            inner = max(1, outer - max(1, size // 40))
            draw.ellipse([x-inner, y-inner, x+inner, y+inner], fill=BG)
        elif i == len(nodes) - 1:
            # Destination: filled magenta, slightly larger
            r2 = nr + max(1, size // 32)
            draw.ellipse([x-r2, y-r2, x+r2, y+r2], fill=MAGENTA)
        else:
            # Intermediate hops: filled cyan
            draw.ellipse([x-nr, y-nr, x+nr, y+nr], fill=CYAN)

    return img


sizes  = [16, 24, 32, 48, 64, 128, 256]
frames = [make_frame(s) for s in sizes]

frames[0].save(
    "cooltr.ico",
    format="ICO",
    sizes=[(s, s) for s in sizes],
    append_images=frames[1:],
)

# Also save a 256-px PNG for README / reference
frames[-1].save("cooltr_icon.png", format="PNG")

print("cooltr.ico  — saved")
print("cooltr_icon.png  — saved (256 px preview)")
