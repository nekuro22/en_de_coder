from PIL import Image
import sys
import os

def convert_to_ico(png_path, ico_path):
    img = Image.open(png_path)
    # Target sizes for windows icons
    icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(ico_path, format='ICO', sizes=icon_sizes)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python convert_icon.py <png_path> <ico_path>")
    else:
        convert_to_ico(sys.argv[1], sys.argv[2])
