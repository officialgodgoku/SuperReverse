"""Liquid-Glass Radial Action Menu for SuperReverse.

Displays interactive petal slices for rapid action dispatch on dropped binaries:
- 🗺️ Generate AI Map
- 🛡️ Security Audit
- 📦 Unpack Artifact
- ☕ Decompile (JADX / ASAR)
- 🔍 Extract Intelligence
- 📋 Copy AI Prompt
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, List, Optional

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import QWidget

from superreverse.ui import glass

R_OUT = 150
R_IN = 62
R_HUB = 52
GAP_DEG = 3.5


@dataclass
class RadialAction:
    id: str
    label: str
    glyph: str
    description: str


DEFAULT_ACTIONS = [
    RadialAction("ai_map", "AI Map", "🗺️", "Generate full AI Architecture Map (.md)"),
    RadialAction("security", "Security", "🛡️", "Mitigations & vulnerability audit"),
    RadialAction("unpack", "Unpack", "📦", "Extract resources, assets & manifest"),
    RadialAction("decompile", "Decompile", "☕", "Run JADX / source recovery"),
    RadialAction("strings", "Strings", "🔍", "Extract URLs, IPs, keys & secrets"),
    RadialAction("copy_prompt", "AI Prompt", "📋", "Copy ready-to-use LLM context"),
]


def sector_path(c: QPointF, r0: float, r1: float, a0: float, a1: float) -> QPainterPath:
    path = QPainterPath()
    outer = QRectF(c.x() - r1, c.y() - r1, 2 * r1, 2 * r1)
    inner = QRectF(c.x() - r0, c.y() - r0, 2 * r0, 2 * r0)
    path.arcMoveTo(outer, a0)
    path.arcTo(outer, a0, a1 - a0)
    path.arcTo(inner, a1, -(a1 - a0))
    path.closeSubpath()
    return path


def angles(n: int, i: int) -> tuple[float, float]:
    span = 360.0 / n
    start = 90 + span / 2 - (i + 1) * span
    return start + GAP_DEG / 2, start + span - GAP_DEG / 2


class RadialDialWidget(QWidget):
    action_selected = Signal(str)

    def __init__(self, parent=None, size: int = 340):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.actions = DEFAULT_ACTIONS
        self.hovered_index: int = -1
        self.setMouseTracking(True)
        self.active_target_name: str = "Drop Software Here"

    def set_target(self, name: str):
        self.active_target_name = name
        self.update()

    def mouseMoveEvent(self, event):
        pos = event.position()
        c = QPointF(self.width() / 2, self.height() / 2)
        dx = pos.x() - c.x()
        dy = pos.y() - c.y()
        dist = math.hypot(dx, dy)

        prev = self.hovered_index
        if R_IN <= dist <= R_OUT:
            # Calculate angle in degrees matching Qt arc convention
            ang = math.degrees(math.atan2(-dy, dx))
            if ang < 0:
                ang += 360

            # Find matching sector
            found = -1
            n = len(self.actions)
            for i in range(n):
                a0, a1 = angles(n, i)
                # Normalize
                norm_a0 = a0 % 360
                norm_a1 = a1 % 360
                if norm_a0 < norm_a1:
                    if norm_a0 <= ang <= norm_a1:
                        found = i
                        break
                else:
                    if ang >= norm_a0 or ang <= norm_a1:
                        found = i
                        break
            self.hovered_index = found
        else:
            self.hovered_index = -1

        if prev != self.hovered_index:
            self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.hovered_index >= 0:
            act = self.actions[self.hovered_index]
            self.action_selected.emit(act.id)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        c = QPointF(self.width() / 2, self.height() / 2)
        n = len(self.actions)

        # 1. Central Hub
        hub_path = QPainterPath()
        hub_path.addEllipse(c, R_HUB, R_HUB)
        glass.paint_liquid_glass(p, hub_path, tint=QColor(24, 20, 36, 230), rim=True)

        # Hub Text
        p.setPen(QColor(255, 255, 255))
        p.setFont(QFont("-apple-system, Segoe UI", 11, QFont.Bold))
        hub_rect = QRectF(c.x() - R_HUB + 4, c.y() - R_HUB + 4, (R_HUB - 4) * 2, (R_HUB - 4) * 2)
        p.drawText(hub_rect, Qt.AlignCenter | Qt.TextWordWrap, "⚡\nSuper\nReverse")

        # 2. Petals
        for i, act in enumerate(self.actions):
            a0, a1 = angles(n, i)
            is_hover = (i == self.hovered_index)
            r_out = R_OUT + (6 if is_hover else 0)
            r_in = R_IN - (2 if is_hover else 0)

            path = sector_path(c, r_in, r_out, a0, a1)
            tint = QColor(45, 35, 75, 230) if is_hover else QColor(20, 18, 30, 180)
            glass.paint_liquid_glass(
                p, path, tint=tint, rim=True, rainbow_alpha=230 if is_hover else 140, highlight=1.3 if is_hover else 0.9
            )

            # Calculate center angle of petal for text placement
            mid_ang = math.radians((a0 + a1) / 2)
            mid_r = (r_in + r_out) / 2
            tx = c.x() + mid_r * math.cos(mid_ang)
            ty = c.y() - mid_r * math.sin(mid_ang)

            p.save()
            p.setPen(QColor(255, 255, 255) if is_hover else QColor(220, 220, 230))
            p.setFont(QFont("-apple-system, Segoe UI", 9, QFont.Bold if is_hover else QFont.Normal))
            rect = QRectF(tx - 35, ty - 18, 70, 36)
            p.drawText(rect, Qt.AlignCenter, f"{act.glyph}\n{act.label}")
            p.restore()
