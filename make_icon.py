"""
Generate cooltr.ico — sonar/radar style network diagnostic icon.
Run once: python make_icon.py
"""
from PIL import Image, ImageDraw
import math

BG      = (6,  10,  24, 255)
CYAN    = (0,  240, 200, 255)
MAGENTA = (255, 20, 170, 255)


def make_frame(size):
    S  = size
    cx = cy = S // 2
    max_r = int(S * 0.46)

    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # ── Background circle ─────────────────────────────────────────────────────
    base = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(base)
    d.ellipse([cx-max_r, cy-max_r, cx+max_r, cy+max_r], fill=BG)
    img = Image.alpha_composite(img, base)

    # ── Concentric rings ──────────────────────────────────────────────────────
    ring_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    rd = ImageDraw.Draw(ring_layer)
    for frac, alpha in ((0.33, 90), (0.66, 110), (1.00, 130)):
        r  = int(max_r * frac)
        lw = max(1, S // 90)
        rd.ellipse([cx-r, cy-r, cx+r, cy+r], outline=(*CYAN[:3], alpha), width=lw)
    img = Image.alpha_composite(img, ring_layer)

    # ── Sweep wedge (filled, fading) ──────────────────────────────────────────
    sweep_deg  = 50    # arm angle in degrees (CCW from east)
    trail_span = 80    # degrees of fade trail behind the arm
    steps      = 60

    for i in range(steps):
        t      = i / steps
        a_deg  = sweep_deg - trail_span * t
        a_next = sweep_deg - trail_span * (i + 1) / steps
        alpha  = int(110 * (1 - t) ** 1.6)

        pts = [(cx, cy)]
        for deg in [a_deg, (a_deg + a_next) / 2, a_next]:
            rad = math.radians(deg)
            pts.append((
                cx + int(max_r * math.cos(rad)),
                cy - int(max_r * math.sin(rad)),
            ))

        layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        ld    = ImageDraw.Draw(layer)
        ld.polygon(pts, fill=(*CYAN[:3], alpha))
        img   = Image.alpha_composite(img, layer)

    # ── Main sweep arm ────────────────────────────────────────────────────────
    arm_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ad = ImageDraw.Draw(arm_layer)
    arm_rad = math.radians(sweep_deg)
    ax = cx + int(max_r * math.cos(arm_rad))
    ay = cy - int(max_r * math.sin(arm_rad))
    lw = max(1, S // 55)
    ad.line([(cx, cy), (ax, ay)], fill=(*CYAN[:3], 230), width=lw)
    img = Image.alpha_composite(img, arm_layer)

    # ── Blips — scattered at different radii & angles within swept area ───────
    blip_defs = [
        (0.32,  -8),   # close hop, near arm
        (0.55, -22),   # mid hop
        (0.80,  -5),   # far hop, near arm
        (0.65, -48),   # mid hop, deep in trail
    ]

    for frac, offset_deg in blip_defs:
        a  = math.radians(sweep_deg + offset_deg)
        bx = cx + int(max_r * frac * math.cos(a))
        by = cy - int(max_r * frac * math.sin(a))

        fade       = max(0.25, 1 - abs(offset_deg) / trail_span)
        glow_alpha = int(55 * fade)
        dot_alpha  = int(230 * fade)
        br         = max(2, S // 32)
        glow       = max(4, S // 14)

        glow_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        gd = ImageDraw.Draw(glow_layer)
        gd.ellipse([bx-glow, by-glow, bx+glow, by+glow], fill=(*MAGENTA[:3], glow_alpha))
        img = Image.alpha_composite(img, glow_layer)

        dot_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        dd = ImageDraw.Draw(dot_layer)
        dd.ellipse([bx-br, by-br, bx+br, by+br], fill=(*MAGENTA[:3], dot_alpha))
        img = Image.alpha_composite(img, dot_layer)

    # ── Center dot ────────────────────────────────────────────────────────────
    center_layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    cd = ImageDraw.Draw(center_layer)
    cr = max(2, S // 38)
    cd.ellipse([cx-cr*2, cy-cr*2, cx+cr*2, cy+cr*2], fill=(*CYAN[:3], 40))
    cd.ellipse([cx-cr,   cy-cr,   cx+cr,   cy+cr  ], fill=CYAN)
    img = Image.alpha_composite(img, center_layer)

    return img


sizes  = [16, 24, 32, 48, 64, 128, 256]
frames = [make_frame(s) for s in sizes]

frames[0].save(
    "cooltr.ico",
    format="ICO",
    sizes=[(s, s) for s in sizes],
    append_images=frames[1:],
)

# 256px PNG for reference
frames[-1].save("cooltr_icon.png", format="PNG")

print("cooltr.ico      — saved")
print("cooltr_icon.png — saved (256 px preview)")
