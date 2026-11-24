import os
from PIL import Image, ImageDraw

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
LOGO_PATH = os.path.join(PROJECT_ROOT, 'web', 'assets', 'logo.png')
RES_DIR = os.path.join(PROJECT_ROOT, 'android', 'app', 'src', 'main', 'res')
ARTIFACT_DIR = r"C:\Users\Aryan\.gemini\antigravity\brain\7de6d289-4dd9-437b-87c8-0b70d966a55b"

DENSITIES = {
    'mipmap-mdpi': 48,
    'mipmap-hdpi': 72,
    'mipmap-xhdpi': 96,
    'mipmap-xxhdpi': 144,
    'mipmap-xxxhdpi': 192,
}

def generate_icons():
    base_logo = Image.open(LOGO_PATH).convert('RGBA')

    for folder, size in DENSITIES.items():
        folder_path = os.path.join(RES_DIR, folder)
        os.makedirs(folder_path, exist_ok=True)

        # 1. Square icon: Pitch black background + scaled centered logo
        square_img = Image.new('RGBA', (size, size), (0, 0, 0, 255))
        # Scale logo with padding (padding 10%)
        content_size = int(size * 0.75)
        scaled_logo = base_logo.resize((content_size, content_size), Image.Resampling.LANCZOS)
        offset = ((size - content_size) // 2, (size - content_size) // 2)
        square_img.paste(scaled_logo, offset, scaled_logo)
        square_img.save(os.path.join(folder_path, 'ic_launcher.png'), 'PNG')

        # 2. Round icon: Circular mask over square icon
        round_img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        mask = Image.new('L', (size, size), 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0, size - 1, size - 1), fill=255)
        round_img.paste(square_img, (0, 0), mask)
        round_img.save(os.path.join(folder_path, 'ic_launcher_round.png'), 'PNG')

    print(f"[OK] Generated launcher icons across {len(DENSITIES)} densities.")

def generate_preview():
    # Create high-res preview grid (1200 x 400)
    preview = Image.new('RGBA', (1200, 400), (18, 18, 24, 255))
    draw = ImageDraw.Draw(preview)

    base_logo = Image.open(LOGO_PATH).convert('RGBA')
    icon_size = 192

    # Square Icon
    square = Image.new('RGBA', (icon_size, icon_size), (0, 0, 0, 255))
    c_size = int(icon_size * 0.75)
    s_logo = base_logo.resize((c_size, c_size), Image.Resampling.LANCZOS)
    square.paste(s_logo, ((icon_size - c_size) // 2, (icon_size - c_size) // 2), s_logo)

    # 1. Square Preview
    preview.paste(square, (50, 100), square)
    draw.text((50, 310), "Standard / Adaptive (192px)", fill=(255, 255, 255))

    # 2. Rounded Square (Corner Radius 36px)
    rounded = Image.new('RGBA', (icon_size, icon_size), (0, 0, 0, 0))
    r_mask = Image.new('L', (icon_size, icon_size), 0)
    ImageDraw.Draw(r_mask).rounded_rectangle((0, 0, icon_size - 1, icon_size - 1), radius=40, fill=255)
    rounded.paste(square, (0, 0), r_mask)
    preview.paste(rounded, (320, 100), rounded)
    draw.text((320, 310), "Rounded Square Mask", fill=(255, 255, 255))

    # 3. Squircle Mask
    squircle = Image.new('RGBA', (icon_size, icon_size), (0, 0, 0, 0))
    sq_mask = Image.new('L', (icon_size, icon_size), 0)
    ImageDraw.Draw(sq_mask).rounded_rectangle((0, 0, icon_size - 1, icon_size - 1), radius=65, fill=255)
    squircle.paste(square, (0, 0), sq_mask)
    preview.paste(squircle, (590, 100), squircle)
    draw.text((590, 310), "Squircle Mask", fill=(255, 255, 255))

    # 4. Circular Mask
    circular = Image.new('RGBA', (icon_size, icon_size), (0, 0, 0, 0))
    c_mask = Image.new('L', (icon_size, icon_size), 0)
    ImageDraw.Draw(c_mask).ellipse((0, 0, icon_size - 1, icon_size - 1), fill=255)
    circular.paste(square, (0, 0), c_mask)
    preview.paste(circular, (860, 100), circular)
    draw.text((860, 310), "Circular Mask", fill=(255, 255, 255))

    # Title
    draw.text((50, 40), "GHOST-TAG ANDROID BRANDING ASSET VALIDATION (PITCH BLACK #000000 / CRISP WHITE #FFFFFF / BLOOD RED #DC2626)", fill=(220, 38, 38))

    preview_path = os.path.join(ARTIFACT_DIR, 'android_branding_preview.png')
    preview.save(preview_path, 'PNG')
    print(f"[OK] Saved preview to {preview_path}")

if __name__ == '__main__':
    generate_icons()
    generate_preview()
