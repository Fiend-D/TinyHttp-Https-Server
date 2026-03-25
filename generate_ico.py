#!/usr/bin/env python3
"""
生成 favicon.ico
"""

from PIL import Image, ImageDraw

# 创建 32x32 的图像
img = Image.new('RGBA', (32, 32), (102, 126, 234, 255))  # 紫色背景
draw = ImageDraw.Draw(img)

# 画一个简单的文件夹图标
# 文件夹主体
draw.rectangle([4, 8, 28, 26], fill=(255, 255, 255, 255), outline=(255, 255, 255, 255))
# 文件夹标签
draw.rectangle([4, 4, 14, 10], fill=(255, 255, 255, 255))

# 保存为 ICO
img.save('static/favicon.ico', format='ICO', sizes=[(16, 16), (32, 32), (48, 48)])

print("favicon.ico generated!")
