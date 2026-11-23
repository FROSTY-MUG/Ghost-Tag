import os
import math
from PIL import Image, ImageDraw

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Exact brand colors
COLOR_BLACK = (0, 0, 0, 255)
COLOR_WHITE = (255, 255, 255, 255)
COLOR_BLOOD_RED = (220, 38, 38, 255) # Hex #DC2626
COLOR_TRANSPARENT = (0, 0, 0, 0)

def draw_brutalist_ghost_tag(draw, x0, y0, width, height, round_mask=False):
    """
    Draws the canonical brutalist Ghost-Tag symbol:
    - Pure black background
    - Crisp geometric white tag body with chamfered top shoulders and notched base
    - Two rectangular eye cutouts
    - One restrained blood-red cryptographic beacon square in upper-right
    """
    w = width
    h = height

    # Proportions based on 64x64 grid:
    # Outer tag: x from 12/64 to 52/64 (width 40/64)
    # y from 10/64 to 54/64 (height 44/64)
    # Chamfers: top-left (12, 24) to (24, 10), top-right (40, 10) to (52, 24)
    # Bottom hem: 3 notches: (52,54)-(44,46)-(36,54)-(28,46)-(20,54)-(12,46)-(12,24)
    
    scale_x = w / 64.0
    scale_y = h / 64.0
    
    # Polygon points scaled
    pts = [
        (x0 + 12 * scale_x, y0 + 24 * scale_y),
        (x0 + 24 * scale_x, y0 + 10 * scale_y),
        (x0 + 40 * scale_x, y0 + 10 * scale_y),
        (x0 + 52 * scale_x, y0 + 24 * scale_y),
        (x0 + 52 * scale_x, y0 + 54 * scale_y),
        (x0 + 44 * scale_x, y0 + 46 * scale_y),
        (x0 + 36 * scale_x, y0 + 54 * scale_y),
        (x0 + 28 * scale_x, y0 + 46 * scale_y),
        (x0 + 20 * scale_x, y0 + 54 * scale_y),
        (x0 + 12 * scale_x, y0 + 46 * scale_y),
    ]
    
    # Draw white silhouette
    draw.polygon(pts, fill=COLOR_WHITE)
    
    # Eye slits (black rectangles)
    # Left eye: x=22 to 28, y=24 to 34
    left_eye = [
        (x0 + 22 * scale_x, y0 + 24 * scale_y),
        (x0 + 28 * scale_x, y0 + 34 * scale_y)
    ]
    draw.rectangle(left_eye, fill=COLOR_BLACK)
    
    # Right eye: x=36 to 42, y=24 to 34
    right_eye = [
        (x0 + 36 * scale_x, y0 + 24 * scale_y),
        (x0 + 42 * scale_x, y0 + 34 * scale_y)
    ]
    draw.rectangle(right_eye, fill=COLOR_BLACK)
    
    # Blood-Red Cryptographic Accent:
    # A restrained, sharp square beacon at upper-right shoulder (x=45 to 50, y=14 to 19)
    accent_rect = [
        (x0 + 45 * scale_x, y0 + 14 * scale_y),
        (x0 + 50 * scale_x, y0 + 19 * scale_y)
    ]
    draw.rectangle(accent_rect, fill=COLOR_BLOOD_RED)

def generate_icon(size, is_round=False, padding_ratio=0.15):
    """Generates an image of given size with the Ghost-Tag branding."""
    img = Image.new('RGBA', (size, size), COLOR_TRANSPARENT if is_round else COLOR_BLACK)
    draw = ImageDraw.Draw(img)
    
    if is_round:
        # Draw circular black background
        draw.ellipse([(0, 0), (size - 1, size - 1)], fill=COLOR_BLACK)
    
    pad = int(size * padding_ratio)
    content_w = size - 2 * pad
    content_h = size - 2 * pad
    
    draw_brutalist_ghost_tag(draw, pad, pad, content_w, content_h)
    
    if is_round:
        # Clip strictly to circle
        mask = Image.new('L', (size, size), 0)
        mask_draw = ImageDraw.Draw(mask)
        mask_draw.ellipse([(0, 0), (size - 1, size - 1)], fill=255)
        round_img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        round_img.paste(img, (0, 0), mask=mask)
        return round_img
        
    return img

def main():
    print("Generating consistent Ghost-Tag brutalist brand assets...")
    
    # 1. Android Mipmap dimensions
    android_res_dir = os.path.join(PROJECT_ROOT, 'android', 'app', 'src', 'main', 'res')
    mipmaps = {
        'mipmap-mdpi': 48,
        'mipmap-hdpi': 72,
        'mipmap-xhdpi': 96,
        'mipmap-xxhdpi': 144,
        'mipmap-xxxhdpi': 192,
    }
    
    for folder, size in mipmaps.items():
        folder_path = os.path.join(android_res_dir, folder)
        os.makedirs(folder_path, exist_ok=True)
        
        # Standard square launcher
        sq_img = generate_icon(size, is_round=False)
        sq_img.save(os.path.join(folder_path, 'ic_launcher.png'), 'PNG')
        
        # Round launcher
        rd_img = generate_icon(size, is_round=True)
        rd_img.save(os.path.join(folder_path, 'ic_launcher_round.png'), 'PNG')
        print(f"  [Android] Generated {folder} (ic_launcher.png & ic_launcher_round.png, {size}x{size})")
        
    # Android Play Store 512x512
    playstore_icon = generate_icon(512, is_round=False)
    playstore_path = os.path.join(PROJECT_ROOT, 'android', 'app', 'src', 'main', 'playstore-icon.png')
    playstore_icon.save(playstore_path, 'PNG')
    print(f"  [Android] Generated playstore-icon.png (512x512)")
    
    # 2. Web Assets
    web_dir = os.path.join(PROJECT_ROOT, 'web')
    web_assets_dir = os.path.join(web_dir, 'assets')
    os.makedirs(web_assets_dir, exist_ok=True)
    
    # 512x512 PNG logo
    web_logo_512 = generate_icon(512, is_round=False)
    web_logo_512.save(os.path.join(web_assets_dir, 'logo.png'), 'PNG')
    print(f"  [Web] Generated web/assets/logo.png (512x512)")
    
    # Favicon sizes: 16, 32, 48
    fav_16 = generate_icon(16, is_round=False, padding_ratio=0.08)
    fav_32 = generate_icon(32, is_round=False, padding_ratio=0.08)
    fav_48 = generate_icon(48, is_round=False, padding_ratio=0.10)
    fav_32.save(os.path.join(web_dir, 'favicon.png'), 'PNG')
    
    # Multi-resolution favicon.ico
    fav_32.save(
        os.path.join(web_dir, 'favicon.ico'),
        format='ICO',
        sizes=[(16, 16), (32, 32), (48, 48)],
        append_images=[fav_16, fav_48]
    )
    print(f"  [Web] Generated web/favicon.ico (16x16, 32x32, 48x48) & web/favicon.png")
    
    # Desktop Ghost Bridge icon
    desktop_assets = os.path.join(PROJECT_ROOT, 'desktop', 'assets')
    os.makedirs(desktop_assets, exist_ok=True)
    desktop_icon = generate_icon(256, is_round=False)
    desktop_icon.save(os.path.join(desktop_assets, 'icon.png'), 'PNG')
    print(f"  [Desktop] Generated desktop/assets/icon.png (256x256)")
    
    # iOS AppIcon asset
    ios_icon_dir = os.path.join(PROJECT_ROOT, 'ios', 'GhostTag', 'Images.xcassets', 'AppIcon.appiconset')
    os.makedirs(ios_icon_dir, exist_ok=True)
    ios_1024 = generate_icon(1024, is_round=False)
    ios_1024.save(os.path.join(ios_icon_dir, 'AppIcon-1024.png'), 'PNG')
    print(f"  [iOS] Generated ios/.../AppIcon-1024.png (1024x1024)")
    
    print("Done generating all brand assets.")

if __name__ == '__main__':
    main()
