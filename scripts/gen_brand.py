"""Generate the full Cauldron brand asset pack from the operator's
hand-drawn pixel sprite. Input is a 256x256 PNG with transparent background
(native sprite at ~8x scale). Output lands in frontend/public/brand and
frontend/public/favicon.* for the existing vite config.

Deliverables:
  - cauldron-native.png           (trimmed 21x25 raw sprite)
  - cauldron-{16,32,48,64,128,256,512}.png   (nearest-neighbour scaled)
  - favicon.ico                   (16/32/48 multi-size)
  - favicon.png                   (32 px modern fallback)
  - apple-touch-icon.png          (180 px with padded background)
  - og-image.png                  (1200x630 social card)
  - github-social.png             (1280x640)
  - cauldron-sidebar.png          (40 px, crisp for UI header @1x/@2x)
  - cauldron.svg                  (rectangle-per-pixel SVG, infinite scale)
  - cauldron-splash.gif           (8-frame sparkle loop)

Nothing here requires rasterising-through-a-bitmap-library beyond PIL;
pixel art deliberately uses NEAREST upscaling to keep crisp edges.
"""
from __future__ import annotations

from pathlib import Path
import numpy as np
from PIL import Image, ImageDraw

ROOT   = Path(r"D:/Projects/cauldron")
# 256x256 is the canonical source — used for SVG (needs highest detail to
# derive native logical pixels), OG/banner art, and the splash (animation
# is drawn at this scale). Smaller sizes have hand-tuned masters because
# pixel art loses legibility under naive downsampling — a 32x32 icon drawn
# to be a 32x32 icon always beats the same sprite auto-shrunk from 256.
SRC    = Path(r"D:/Cauldron/data/logo/New_Piskel_256x256.png")

# Hand-tuned masters per display size. The generator prefers these over
# derivation; when a requested size has no master we scale from the nearest
# master with NEAREST to preserve pixel crispness.
SIZE_MASTERS: dict[int, Path] = {
    32:  Path(r"D:/Cauldron/data/logo/New_Piskel_32x32.png"),
    64:  Path(r"D:/Cauldron/data/logo/New_Piskel_64x64.png"),
    128: Path(r"D:/Cauldron/data/logo/New_Piskel_128x128.png"),
    256: Path(r"D:/Cauldron/data/logo/New_Piskel_256x256.png"),
}

# Optional hand-drawn animation — used for splash / progress companion.
ANIM_SRC = Path(r"D:/Cauldron/data/logo/New_Piskel.gif")

PUB    = ROOT / "frontend" / "public"
BRAND  = PUB / "brand"
BRAND.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Load + trim + detect native scale
# ---------------------------------------------------------------------------

img = Image.open(SRC).convert("RGBA")
arr = np.array(img)

# Crop to content (non-transparent)
mask = arr[:, :, 3] > 0
ys, xs = np.where(mask)
y0, y1, x0, x1 = ys.min(), ys.max() + 1, xs.min(), xs.max() + 1
cropped = img.crop((x0, y0, x1, y1))

# Native pixel scale: dominant run-length of same-colour pixels in a mid-row
mid = np.array(cropped)[(y1 - y0) // 2]
runs, cur, run = [], tuple(mid[0]), 1
for i in range(1, len(mid)):
    c = tuple(mid[i])
    if c == cur:
        run += 1
    else:
        if run >= 2 and cur[3] > 0:
            runs.append(run)
        run, cur = 1, c
from collections import Counter
scale = Counter(runs).most_common(1)[0][0]

native_w = cropped.width  // scale
native_h = cropped.height // scale
native = cropped.resize((native_w, native_h), Image.NEAREST)  # one pixel per logical
print(f"[info] trimmed {cropped.size}, scale x{scale}, native {native.size}")

# ---------------------------------------------------------------------------
# Multi-resolution PNGs (nearest-neighbour so pixels stay sharp)
# ---------------------------------------------------------------------------

def upscale(size: int) -> Image.Image:
    """Return a size×size RGBA PNG for the logo at the given display size.

    Priority:
      1. If a hand-tuned master exists at exactly ``size``, use it as-is.
         The operator has already solved the "how much detail survives at
         this pixel density" problem; auto-scaling from a different master
         would re-introduce the loss they already fixed.
      2. Otherwise, pick the smallest master >= size and NEAREST-downscale
         by an integer factor when possible (16 from 32, 48 from no master
         → fall through to smaller master + pad, etc.).
      3. For sizes larger than every master, integer NEAREST-upscale the
         largest master so pixels stay crisp.

    Every result is a square canvas with transparent padding when the
    sprite is non-square or smaller than target — no stretching, so the
    pixel art's aspect ratio is always preserved.
    """
    # Direct master hit — no scaling, just potential centering on a square
    # canvas (the operator's 32/64/128/256 masters are already square).
    if size in SIZE_MASTERS:
        img = Image.open(SIZE_MASTERS[size]).convert("RGBA")
        if img.size == (size, size):
            return img
        # Master exists but non-square — pad to square
        canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        canvas.paste(img, ((size - img.width) // 2, (size - img.height) // 2), img)
        return canvas

    masters_asc = sorted(SIZE_MASTERS.keys())

    # Larger than every master — upscale the biggest with integer NEAREST.
    if size > masters_asc[-1]:
        src = Image.open(SIZE_MASTERS[masters_asc[-1]]).convert("RGBA")
        factor = max(1, size // src.width)
        scaled = src.resize((src.width * factor, src.height * factor), Image.NEAREST)
        canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        canvas.paste(scaled, ((size - scaled.width) // 2, (size - scaled.height) // 2), scaled)
        return canvas

    # Smaller than the smallest master OR between masters — pick the
    # smallest master that is >= the requested size and NEAREST-downscale.
    # Downscaling from a master close in size preserves detail best.
    for m in masters_asc:
        if m >= size:
            src = Image.open(SIZE_MASTERS[m]).convert("RGBA")
            return src.resize((size, size), Image.NEAREST)

    # Unreachable — the "larger than every master" branch above handles it.
    src = Image.open(SIZE_MASTERS[masters_asc[-1]]).convert("RGBA")
    return src.resize((size, size), Image.NEAREST)

native.save(BRAND / "cauldron-native.png")
for s in (16, 32, 48, 64, 128, 256, 512):
    upscale(s).save(BRAND / f"cauldron-{s}.png")
    print(f"[png ] {s:>3}x{s}")
# Sidebar header uses cauldron.svg (below) because it scales crisply to
# any zoom/DPI; no per-size raster needed for the header.

# ---------------------------------------------------------------------------
# Favicon
# ---------------------------------------------------------------------------

# favicon.ico carries 16+32+48 as the standard browser tab sizes.
favicon_path = PUB / "favicon.ico"
# Replace vite's default svg favicon with raster pack so browsers pick the
# best size; keep the SVG as /brand/cauldron.svg for HiDPI consumers.
upscale(16).save(
    favicon_path,
    format="ICO",
    sizes=[(16, 16), (32, 32), (48, 48)],
)
print(f"[ico ] favicon.ico (16/32/48)")

# Modern PNG favicon
upscale(32).save(PUB / "favicon-32.png")
upscale(192).save(PUB / "favicon-192.png")  # PWA manifest size
upscale(180).save(PUB / "apple-touch-icon.png")
print(f"[png ] favicon-32 / favicon-192 / apple-touch-icon")

# ---------------------------------------------------------------------------
# Social / README banners (padded, dark background)
# ---------------------------------------------------------------------------

BG = (15, 17, 23, 255)  # bg-gray-950-ish for social cards
INDIGO = (129, 140, 248, 255)  # indigo-400 — brand accent

# Try a set of fonts in preference order (cross-OS friendly). We fall back
# to PIL's bundled font when nothing is found so the script remains
# reproducible, but the banner only looks right with real type.
from PIL import ImageFont
import os
def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for p in (
        "C:/Windows/Fonts/segoeuib.ttf",   # Windows bold
        "C:/Windows/Fonts/segoeui.ttf",    # Windows regular
        "/System/Library/Fonts/Helvetica.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ):
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                continue
    return ImageFont.load_default()

def banner(width: int, height: int, title: str, subtitle: str) -> Image.Image:
    bg = Image.new("RGBA", (width, height), BG)
    # Logo fills ~70% of height, integer scale for crispness.
    target_h = int(height * 0.70)
    lscale = max(1, target_h // native.height)
    logo = native.resize(
        (native.width * lscale, native.height * lscale), Image.NEAREST,
    )
    lx = int(width * 0.10)
    ly = (height - logo.height) // 2
    bg.paste(logo, (lx, ly), logo)

    # Typography: large title + smaller subtitle, dark-theme palette.
    title_size    = int(height * 0.17)
    subtitle_size = int(height * 0.07)
    title_font    = _font(title_size)
    subtitle_font = _font(subtitle_size)
    draw = ImageDraw.Draw(bg)
    tx = lx + logo.width + int(width * 0.05)
    # Center the two-line block vertically against the logo's middle.
    block_h = title_size + subtitle_size + int(height * 0.04)
    ty = (height - block_h) // 2
    draw.text((tx, ty), title, font=title_font, fill=(229, 231, 235, 255))
    draw.text(
        (tx, ty + title_size + int(height * 0.04)),
        subtitle, font=subtitle_font, fill=INDIGO,
    )
    return bg

banner(1200, 630,  "Cauldron",
       "Network Attack Path Discovery").save(BRAND / "og-image.png")
banner(1280, 640,  "Cauldron",
       "Network Attack Path Discovery").save(BRAND / "github-social.png")
print("[png ] og-image 1200x630 / github-social 1280x640")

# ---------------------------------------------------------------------------
# Pixel-perfect SVG (rectangle-per-pixel) for infinite scalability
# ---------------------------------------------------------------------------

def svg_from_pixels(img: Image.Image) -> str:
    w, h = img.size
    pixels = np.array(img)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        'shape-rendering="crispEdges">',
    ]
    # Group runs of same-colour consecutive pixels on a row into one <rect>
    # so the SVG stays small even though the sprite has 500+ coloured cells.
    for y in range(h):
        x = 0
        while x < w:
            r, g, b, a = pixels[y, x]
            if a == 0:
                x += 1
                continue
            start = x
            while x < w and tuple(pixels[y, x]) == (r, g, b, a):
                x += 1
            run = x - start
            opacity = "" if a == 255 else f' fill-opacity="{a/255:.3f}"'
            parts.append(
                f'<rect x="{start}" y="{y}" width="{run}" height="1" '
                f'fill="#{r:02x}{g:02x}{b:02x}"{opacity}/>'
            )
    parts.append("</svg>")
    return "".join(parts)

svg = svg_from_pixels(native)
(BRAND / "cauldron.svg").write_text(svg, encoding="utf-8")
print(f"[svg ] cauldron.svg ({len(svg)} bytes)")

# ---------------------------------------------------------------------------
# Animated splash — prefer operator's hand-drawn animation when available,
# fall back to procedural sparkle-flicker when only a static source exists.
# ---------------------------------------------------------------------------

def load_animation_frames(gif_path: Path) -> list[Image.Image] | None:
    """Load a GIF, trim each frame to the static logo's content bbox so the
    splash can't jitter around inside transparent padding, and return native
    1x pixel frames (one colour-cell per pixel)."""
    if not gif_path.exists():
        return None
    g = Image.open(gif_path)
    frames: list[Image.Image] = []
    durations: list[int] = []
    for i in range(getattr(g, "n_frames", 1)):
        g.seek(i)
        f = g.convert("RGBA").crop((x0, y0, x1, y1))
        # Downsample at the same scale we used for the static sprite so the
        # splash output has the same native resolution as cauldron-native.png
        # and composites cleanly onto any other brand asset.
        f = f.resize((f.width // scale, f.height // scale), Image.NEAREST)
        frames.append(f)
        durations.append(g.info.get("duration", 100))
    return frames if frames else None

anim = load_animation_frames(ANIM_SRC)
if anim:
    splash_frames = anim
    splash_duration = 80  # 12 frames * 80 = 960ms loop, matches source
    source_tag = f"operator animation ({len(anim)} frames)"
else:
    SPARKLE_COLORS = {
        (0xff, 0x9f, 0x4a, 0xff), (0xff, 0x60, 0x36, 0xff),
        (0xff, 0xda, 0x5c, 0xff),
    }
    base = np.array(native.copy())
    sparkle_mask = np.zeros(base.shape[:2], dtype=bool)
    for sy in range(base.shape[0]):
        for sx in range(base.shape[1]):
            if tuple(base[sy, sx]) in SPARKLE_COLORS:
                sparkle_mask[sy, sx] = True
    sparkle_coords = np.argwhere(sparkle_mask)
    rng = np.random.default_rng(seed=42)
    splash_frames = []
    for f in range(8):
        frame = base.copy()
        drop = rng.random(len(sparkle_coords)) < 0.35
        for (sy, sx), d in zip(sparkle_coords, drop):
            if d:
                frame[sy, sx] = (0, 0, 0, 0)
        splash_frames.append(Image.fromarray(frame, "RGBA"))
    splash_duration = 150
    source_tag = "procedural sparkle-flicker (no animation source)"

# Splash displayed at 4x for crispness; preserve each frame's duration when
# driven from the hand-drawn source, otherwise use the flat sparkle timing.
SPLASH_SCALE = 4
big_frames = [
    f.resize((f.width * SPLASH_SCALE, f.height * SPLASH_SCALE), Image.NEAREST)
    for f in splash_frames
]

# GIF: flatten alpha onto a dark background — format only supports 1-bit
# transparency, so we bake against bg-gray-950 for the canonical splash
# screen usage.
flat_frames = []
for f in big_frames:
    bg = Image.new("RGB", f.size, (15, 17, 23))
    bg.paste(f, (0, 0), f)
    flat_frames.append(bg.convert("P", palette=Image.ADAPTIVE, colors=64))
flat_frames[0].save(
    BRAND / "cauldron-splash.gif",
    save_all=True,
    append_images=flat_frames[1:],
    duration=splash_duration,
    loop=0,
    disposal=2,
)
print(f"[gif ] cauldron-splash.gif ({len(big_frames)} frames @ {splash_duration}ms, {source_tag})")

# WebP: keeps full alpha so the splash can sit over any background —
# sidebar header, progress bar, loading screen — without a baked square.
try:
    big_frames[0].save(
        BRAND / "cauldron-splash.webp",
        save_all=True,
        append_images=big_frames[1:],
        duration=splash_duration,
        loop=0,
        lossless=True,
    )
    print(f"[webp] cauldron-splash.webp ({len(big_frames)} frames, alpha preserved)")
except Exception as e:
    print(f"[warn] webp save failed: {e}")

# Small-size companion animation for inline UI use (progress bars, loading
# hints). 32x32 alpha-preserved webp — sits next to text without dominating.
try:
    small_frames = [
        f.resize((32, 32 * f.height // f.width), Image.NEAREST)
        for f in splash_frames
    ]
    small_frames[0].save(
        BRAND / "cauldron-anim-32.webp",
        save_all=True,
        append_images=small_frames[1:],
        duration=splash_duration,
        loop=0,
        lossless=True,
    )
    print(f"[webp] cauldron-anim-32.webp (inline UI size)")
except Exception as e:
    print(f"[warn] small webp failed: {e}")

print()
print(f"All assets in: {BRAND}")
print(f"Favicon:       {PUB / 'favicon.ico'}")
