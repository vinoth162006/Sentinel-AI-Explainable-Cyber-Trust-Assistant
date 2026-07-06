import os
import subprocess
import sys

# Ensure Pillow is installed
try:
    from PIL import Image, ImageDraw
except ImportError:
    print("Pillow not found. Installing Pillow...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
    from PIL import Image, ImageDraw

def create_shield_icon(size):
    # Create image with transparent background
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Scale coordinates based on size
    s = size
    
    # Shield shape points
    # Outer shield polygon
    shield_pts = [
        (s * 0.5, s * 0.1),    # Top center
        (s * 0.85, s * 0.22),  # Top right
        (s * 0.85, s * 0.55),  # Mid right
        (s * 0.5, s * 0.9),    # Bottom tip
        (s * 0.15, s * 0.55),  # Mid left
        (s * 0.15, s * 0.22),  # Top left
    ]
    
    # Inner shield (for double border effect)
    inner_pts = [
        (s * 0.5, s * 0.18),
        (s * 0.77, s * 0.28),
        (s * 0.77, s * 0.53),
        (s * 0.5, s * 0.82),
        (s * 0.23, s * 0.53),
        (s * 0.23, s * 0.28),
    ]

    # Draw outer shield fill (Dark metallic blue)
    draw.polygon(shield_pts, fill=(18, 24, 36, 255))
    
    # Draw outer boundary border (Sleek light blue)
    draw.polygon(shield_pts, outline=(59, 130, 246, 255), width=max(1, int(s * 0.05)))
    
    # Draw inner line (Neon Cyan)
    draw.polygon(inner_pts, outline=(6, 182, 212, 255), width=max(1, int(s * 0.02)))
    
    # Draw a pulsing central core circle (Emerald Green)
    core_radius = s * 0.12
    cx, cy = s * 0.5, s * 0.45
    draw.ellipse(
        [cx - core_radius, cy - core_radius, cx + core_radius, cy + core_radius],
        fill=(16, 185, 129, 255),
        outline=(52, 211, 153, 255),
        width=max(1, int(s * 0.02))
    )
    
    # Make sure output folder exists
    os.makedirs(os.path.dirname(f"d:/sentinel-ai/extension/icons/icon{size}.png"), exist_ok=True)
    img.save(f"d:/sentinel-ai/extension/icons/icon{size}.png")
    print(f"Generated icon{size}.png successfully.")

if __name__ == "__main__":
    sizes = [16, 48, 128]
    for size in sizes:
        create_shield_icon(size)
    print("All icons generated successfully.")
