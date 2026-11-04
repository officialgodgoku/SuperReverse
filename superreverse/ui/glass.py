"""Liquid-glass styling, shaders, and QSS for SuperReverse.

Produces iridescent rim dispersion, frosted glass blur, and modern dark translucent widgets.
"""
from __future__ import annotations

import sys
from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QConicalGradient,
    QImage,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
)
from PySide6.QtWidgets import QWidget

IRIDESCENT = [
    "#ff6b9d", "#ffb36b", "#ffe66b", "#7dffb0", "#6bd5ff", "#8a7bff", "#e07bff", "#ff6b9d"
]

TEXT = "#ffffff"
TEXT_DIM = "rgba(255,255,255,0.68)"
ACCENT_CYAN = "#00f0ff"
ACCENT_PURPLE = "#8a7bff"
ACCENT_PINK = "#ff007f"
ACCENT_GREEN = "#00ff88"


def iridescent_pen(center: QPointF, width: float = 1.4, alpha: int = 180, angle: float = 45) -> QPen:
    g = QConicalGradient(center, angle)
    n = len(IRIDESCENT) - 1
    for i, c in enumerate(IRIDESCENT):
        col = QColor(c)
        col.setAlpha(alpha)
        g.setColorAt(i / n, col)
    return QPen(QBrush(g), width)


def iridescent_brush(rect: QRectF, alpha: int = 40) -> QBrush:
    g = QLinearGradient(rect.topLeft(), rect.bottomRight())
    n = len(IRIDESCENT) - 1
    for i, c in enumerate(IRIDESCENT):
        col = QColor(c)
        col.setAlpha(alpha)
        g.setColorAt(i / n, col)
    return QBrush(g)


def paint_liquid_glass(
    p: QPainter,
    path: QPainterPath,
    tint: QColor | None = None,
    rim: bool = True,
    rainbow_alpha: int = 180,
    highlight: float = 1.0,
) -> None:
    rect = path.boundingRect()
    p.save()
    p.setRenderHint(QPainter.Antialiasing)
    p.setClipPath(path)

    # 1. Dark glass base tint
    base_tint = tint or QColor(18, 16, 26, 215)
    p.fillPath(path, base_tint)

    # 2. Iridescent light wash
    p.fillPath(path, iridescent_brush(rect, 22))

    # 3. Top specular sheen
    sheen = QLinearGradient(rect.topLeft(), QPointF(rect.left(), rect.top() + rect.height() * 0.45))
    sheen.setColorAt(0.0, QColor(255, 255, 255, int(65 * highlight)))
    sheen.setColorAt(1.0, QColor(255, 255, 255, 0))
    p.fillPath(path, sheen)

    # 4. Corner caustics glow
    glow = QRadialGradient(
        QPointF(rect.right() - rect.width() * 0.25, rect.bottom() - rect.height() * 0.2),
        max(rect.width(), rect.height()) * 0.55,
    )
    glow.setColorAt(0.0, QColor(0, 240, 255, int(20 * highlight)))
    glow.setColorAt(1.0, QColor(0, 0, 0, 0))
    p.fillPath(path, glow)
    p.restore()

    # 5. Iridescent border & specular rim
    if rim:
        p.save()
        p.setRenderHint(QPainter.Antialiasing)

        # Specular gradient edge
        spec = QLinearGradient(rect.topLeft(), rect.bottomRight())
        spec.setColorAt(0.0, QColor(255, 255, 255, int(220 * min(1.0, highlight))))
        spec.setColorAt(0.4, QColor(255, 255, 255, 50))
        spec.setColorAt(0.7, QColor(255, 255, 255, 30))
        spec.setColorAt(1.0, QColor(255, 255, 255, 140))
        p.setPen(QPen(QBrush(spec), 1.2))
        p.drawPath(path)

        # Subtle chromatic rainbow pen
        p.setPen(iridescent_pen(rect.center(), 1.4, rainbow_alpha))
        p.drawPath(path)
        p.restore()


QSS = f"""
* {{
    color: {TEXT};
    font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
    font-size: 10pt;
}}

QWidget#glassRoot {{
    background: transparent;
}}

QLabel#title {{
    font-size: 12pt;
    font-weight: 700;
    letter-spacing: 0.5px;
}}

QLabel#subtitle {{
    color: {TEXT_DIM};
    font-size: 9pt;
}}

QLabel#badge {{
    background: rgba(0, 240, 255, 0.15);
    border: 1px solid rgba(0, 240, 255, 0.4);
    border-radius: 8px;
    padding: 3px 8px;
    font-size: 8.5pt;
    font-weight: 600;
    color: #5ac8ff;
}}

QFrame#card {{
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 14px;
}}

QFrame#dropZone {{
    background: rgba(255, 255, 255, 0.03);
    border: 2px dashed rgba(255, 255, 255, 0.25);
    border-radius: 18px;
}}

QFrame#dropZone:hover, QFrame#dropZone[active="true"] {{
    background: rgba(0, 240, 255, 0.08);
    border: 2px dashed rgba(0, 240, 255, 0.7);
}}

QPushButton {{
    background: rgba(255, 255, 255, 0.10);
    border: 1px solid rgba(255, 255, 255, 0.22);
    border-top-color: rgba(255, 255, 255, 0.45);
    border-bottom-color: rgba(255, 255, 255, 0.12);
    border-radius: 12px;
    padding: 6px 14px;
    font-weight: 500;
}}

QPushButton:hover {{
    background: rgba(255, 255, 255, 0.18);
    border-color: rgba(255, 255, 255, 0.4);
}}

QPushButton:pressed {{
    background: rgba(255, 255, 255, 0.06);
}}

QPushButton#primary {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {ACCENT_CYAN}, stop:0.55 {ACCENT_PURPLE}, stop:1 {ACCENT_PINK});
    border: 1px solid rgba(255, 255, 255, 0.6);
    border-top-color: rgba(255, 255, 255, 0.9);
    color: #ffffff;
    font-weight: 700;
    border-radius: 14px;
    padding: 8px 18px;
}}

QPushButton#primary:hover {{
    border-color: #ffffff;
}}

QPushButton#chrome {{
    background: transparent;
    border: none;
    padding: 4px 10px;
    font-size: 11pt;
    border-radius: 6px;
}}

QPushButton#chrome:hover {{
    background: rgba(255, 80, 100, 0.5);
}}

QTabWidget::pane {{
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 12px;
    background: rgba(12, 10, 20, 0.65);
}}

QTabBar::tab {{
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    padding: 6px 14px;
    margin-right: 4px;
    color: {TEXT_DIM};
}}

QTabBar::tab:selected {{
    background: rgba(255, 255, 255, 0.14);
    border-color: rgba(255, 255, 255, 0.35);
    color: #ffffff;
    font-weight: 600;
}}

QTextEdit, QPlainTextEdit {{
    background: rgba(10, 8, 16, 0.75);
    border: 1px solid rgba(255, 255, 255, 0.15);
    border-radius: 10px;
    padding: 8px;
    font-family: "Consolas", "Cascadia Code", "Fira Code", monospace;
    font-size: 9.5pt;
    color: #e6e6e6;
    selection-background-color: {ACCENT_PURPLE};
}}

QProgressBar {{
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.18);
    border-radius: 8px;
    text-align: center;
    font-weight: 600;
}}

QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {ACCENT_CYAN}, stop:0.5 {ACCENT_PURPLE}, stop:1 {ACCENT_PINK});
    border-radius: 7px;
}}
"""
