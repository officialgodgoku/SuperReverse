"""Render ultra-high quality vector-rendered icons and banners using Qt QPainter."""
import math
import sys
from pathlib import Path
from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QConicalGradient,
    QFont,
    QImage,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import QApplication

root = Path(__file__).resolve().parent.parent
docs_dir = root / "docs"
assets_dir = root / "superreverse" / "assets"
docs_dir.mkdir(parents=True, exist_ok=True)
assets_dir.mkdir(parents=True, exist_ok=True)

app = QApplication.instance() or QApplication(sys.argv)


def draw_cyber_icon(size: int = 512) -> QImage:
    img = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    img.fill(Qt.transparent)

    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    p.setRenderHint(QPainter.SmoothPixmapTransform)

    margin = size * 0.05
    rect = QRectF(margin, margin, size - 2 * margin, size - 2 * margin)
    r = size * 0.22

    # 1. Base Squircle with dark metallic cosmic gradient
    base_grad = QLinearGradient(rect.topLeft(), rect.bottomRight())
    base_grad.setColorAt(0.0, QColor(24, 20, 38))
    base_grad.setColorAt(0.5, QColor(14, 12, 22))
    base_grad.setColorAt(1.0, QColor(8, 6, 14))

    path = QPainterPath()
    path.addRoundedRect(rect, r, r)
    p.fillPath(path, base_grad)

    # 2. Ambient backlight glow
    p.save()
    p.setClipPath(path)
    glow = QRadialGradient(QPointF(size * 0.5, size * 0.5), size * 0.5)
    glow.setColorAt(0.0, QColor(0, 240, 255, 60))
    glow.setColorAt(0.5, QColor(138, 123, 255, 30))
    glow.setColorAt(1.0, QColor(0, 0, 0, 0))
    p.fillPath(path, glow)

    # Top Sheen
    sheen = QLinearGradient(rect.topLeft(), QPointF(rect.left(), rect.top() + rect.height() * 0.45))
    sheen.setColorAt(0.0, QColor(255, 255, 255, 65))
    sheen.setColorAt(1.0, QColor(255, 255, 255, 0))
    p.fillPath(path, sheen)
    p.restore()

    # 3. Iridescent Outer Rim
    irid = [
        QColor("#ff6b9d"), QColor("#ffb36b"), QColor("#ffe66b"),
        QColor("#7dffb0"), QColor("#6bd5ff"), QColor("#8a7bff"),
        QColor("#e07bff"), QColor("#ff6b9d"),
    ]
    conic = QConicalGradient(rect.center(), 45)
    for i, c in enumerate(irid):
        conic.setColorAt(i / (len(irid) - 1), c)

    p.save()
    p.setPen(QPen(QBrush(conic), size * 0.016))
    p.drawPath(path)
    p.restore()

    # 4. Center Reverse Engineering Glyph (Dual Reversing Orbital Arcs + Lightning Core)
    c = rect.center()
    p.save()
    p.translate(c)

    # Circular orbit track
    p.setPen(QPen(QColor(255, 255, 255, 25), size * 0.012))
    p.drawEllipse(QPointF(0, 0), size * 0.28, size * 0.28)

    # Reverse Arc 1 (Cyan)
    arc_pen1 = QPen(QColor(0, 240, 255, 240), size * 0.038)
    arc_pen1.setCapStyle(Qt.RoundCap)
    p.setPen(arc_pen1)
    arc_rect1 = QRectF(-size * 0.28, -size * 0.28, size * 0.56, size * 0.56)
    p.drawArc(arc_rect1, 30 * 16, 120 * 16)

    # Reverse Arrow 1
    p.setBrush(QColor(0, 240, 255))
    a1_path = QPainterPath()
    a1_x = size * 0.28 * math.cos(math.radians(-150))
    a1_y = size * 0.28 * math.sin(math.radians(-150))
    a1_path.moveTo(a1_x, a1_y)
    a1_path.lineTo(a1_x + size * 0.04, a1_y - size * 0.05)
    a1_path.lineTo(a1_x - size * 0.02, a1_y - size * 0.06)
    a1_path.closeSubpath()
    p.drawPath(a1_path)

    # Reverse Arc 2 (Pink/Violet)
    arc_pen2 = QPen(QColor(255, 107, 157, 240), size * 0.038)
    arc_pen2.setCapStyle(Qt.RoundCap)
    p.setPen(arc_pen2)
    p.drawArc(arc_rect1, 210 * 16, 120 * 16)

    # Central Neon Lightning / Diamond Core
    core = QPainterPath()
    s = size * 0.22
    core.moveTo(s * 0.1, -s * 0.9)
    core.lineTo(-s * 0.5, 0.0)
    core.lineTo(0.0, 0.0)
    core.lineTo(-s * 0.2, s * 0.9)
    core.lineTo(s * 0.6, -s * 0.05)
    core.lineTo(s * 0.05, -s * 0.05)
    core.closeSubpath()

    core_glow = QLinearGradient(QPointF(0, -s), QPointF(0, s))
    core_glow.setColorAt(0.0, QColor(255, 235, 100))
    core_glow.setColorAt(0.6, QColor(0, 240, 255))
    core_glow.setColorAt(1.0, QColor(138, 123, 255))

    p.setPen(QPen(QColor(255, 255, 255, 220), size * 0.015))
    p.setBrush(QBrush(core_glow))
    p.drawPath(core)

    p.restore()
    p.end()
    return img


def generate_ico_and_png():
    img512 = draw_cyber_icon(512)
    img512.save(str(assets_dir / "icon.png"), "PNG")
    img512.save(str(docs_dir / "logo.png"), "PNG")

    # Also build Windows .ICO with multiple resolutions
    sizes = [256, 128, 64, 48, 32, 16]
    from PIL import Image
    pil_img = Image.open(str(assets_dir / "icon.png"))
    pil_img.save(str(assets_dir / "icon.ico"), format="ICO", sizes=[(s, s) for s in sizes])
    pil_img.save(str(root / "superreverse.ico"), format="ICO", sizes=[(s, s) for s in sizes])
    print("[+] Created icon.png and icon.ico (multi-res)")


def draw_github_banner():
    w, h = 1200, 380
    img = QImage(w, h, QImage.Format_ARGB32_Premultiplied)
    img.fill(QColor(13, 11, 20))

    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    p.setRenderHint(QPainter.TextAntialiasing)
    p.setRenderHint(QPainter.SmoothPixmapTransform)

    # Ambient subtle grid
    p.setPen(QPen(QColor(255, 255, 255, 10), 1))
    for x in range(0, w, 40):
        p.drawLine(x, 0, x, h)
    for y in range(0, h, 40):
        p.drawLine(0, y, w, y)

    # Background ambient radial light
    rad = QRadialGradient(QPointF(240, h / 2), 340)
    rad.setColorAt(0.0, QColor(0, 240, 255, 45))
    rad.setColorAt(0.6, QColor(138, 123, 255, 20))
    rad.setColorAt(1.0, QColor(0, 0, 0, 0))
    p.fillRect(0, 0, w, h, QBrush(rad))

    # Draw App Logo on Left
    icon_img = draw_cyber_icon(240)
    p.drawImage(80, (h - 240) // 2, icon_img)

    # Typography on Right
    tx = 360
    # Title
    p.setPen(QColor(255, 255, 255))
    font_title = QFont("-apple-system, Segoe UI", 42, QFont.Bold)
    font_title.setLetterSpacing(QFont.AbsoluteSpacing, 1.5)
    p.setFont(font_title)
    p.drawText(tx, 130, "SuperReverse")

    # Tagline
    p.setPen(QColor(0, 240, 255))
    font_sub = QFont("-apple-system, Segoe UI", 16, QFont.DemiBold)
    p.setFont(font_sub)
    p.drawText(tx, 175, "Autonomous AI Software & Web Architecture Mapper")

    # Capabilities Pill Line
    p.setPen(QColor(200, 200, 225))
    font_body = QFont("-apple-system, Segoe UI", 13)
    p.setFont(font_body)
    p.drawText(tx, 220, "APK / AAB • Windows PE • Electron ASAR • Linux ELF • Web URLs • WASM")

    p.setPen(QColor(160, 160, 190))
    font_meta = QFont("-apple-system, Segoe UI", 12)
    p.setFont(font_meta)
    p.drawText(tx, 255, "Deep REA & APK-Reverse Engine in Liquid-Glass • Auto-generates AI Maps")

    # Author & Sponsor badge
    p.setPen(QColor(255, 221, 0))
    font_author = QFont("-apple-system, Segoe UI", 13, QFont.Bold)
    p.setFont(font_author)
    p.drawText(tx, 305, "Created with 💖 by Manish (@officialgodgoku)  •  ☕ Buy Me a Coffee")

    p.end()
    img.save(str(docs_dir / "banner.png"), "PNG")
    print("[+] Created docs/banner.png with crisp Qt typography")


if __name__ == "__main__":
    generate_ico_and_png()
    draw_github_banner()
