"""Liquid-Glass Radial Action Menu for SuperReverse.

Displays interactive petal slices for rapid action dispatch on dropped binaries:
- 🗺️ Generate AI Map
- 🛡️ Security Audit
- 📦 Unpack Artifact
- ☕ Decompile (JADX / ASAR / Capstone)
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
    QCursor,
    QDragEnterEvent,
    QDragLeaveEvent,
    QDragMoveEvent,
    QDropEvent,
    QFont,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import QToolTip, QWidget

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
    RadialAction("security", "Security", "🛡️", "Mitigations, risks & security audit"),
    RadialAction("unpack", "Unpack", "📦", "Extract resources, assets, manifest & files"),
    RadialAction("decompile", "Decompile", "☕", "Run JADX / Capstone assembly viewer"),
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
    action_dropped = Signal(str, str)  # action_id, target_path
    hub_clicked = Signal()

    def __init__(self, parent=None, size: int = 340):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.actions = DEFAULT_ACTIONS
        self.hovered_index: int = -1
        self.pressed_index: int = -1
        self.hub_hovered: bool = False
        self.hub_pressed: bool = False
        self.setMouseTracking(True)
        self.setAcceptDrops(True)
        self.active_target_name: str = "Drop Software Here"

    def set_target(self, name: str):
        self.active_target_name = name
        self.update()

    def _get_sector_at(self, pos: QPointF) -> int:
        c = QPointF(self.width() / 2, self.height() / 2)
        dx = pos.x() - c.x()
        dy = pos.y() - c.y()
        dist = math.hypot(dx, dy)

        if R_IN <= dist <= R_OUT + 8:
            ang = math.degrees(math.atan2(-dy, dx))
            if ang < 0:
                ang += 360

            n = len(self.actions)
            for i in range(n):
                a0, a1 = angles(n, i)
                norm_a0 = a0 % 360
                norm_a1 = a1 % 360
                if norm_a0 < norm_a1:
                    if norm_a0 <= ang <= norm_a1:
                        return i
                else:
                    if ang >= norm_a0 or ang <= norm_a1:
                        return i
        return -1

    def mouseMoveEvent(self, event):
        pos = event.position()
        c = QPointF(self.width() / 2, self.height() / 2)
        dist = math.hypot(pos.x() - c.x(), pos.y() - c.y())

        prev_hover = self.hovered_index
        prev_hub = self.hub_hovered

        if dist <= R_HUB:
            self.hub_hovered = True
            self.hovered_index = -1
            self.setCursor(QCursor(Qt.PointingHandCursor))
        else:
            self.hub_hovered = False
            self.hovered_index = self._get_sector_at(pos)
            if self.hovered_index >= 0:
                self.setCursor(QCursor(Qt.PointingHandCursor))
                act = self.actions[self.hovered_index]
                self.setToolTip(f"{act.glyph} {act.label}: {act.description}")
            else:
                self.setCursor(QCursor(Qt.ArrowCursor))
                self.setToolTip("")

        if prev_hover != self.hovered_index or prev_hub != self.hub_hovered:
            self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            pos = event.position()
            c = QPointF(self.width() / 2, self.height() / 2)
            dist = math.hypot(pos.x() - c.x(), pos.y() - c.y())
            if dist <= R_HUB:
                self.hub_pressed = True
                self.pressed_index = -2
            else:
                self.pressed_index = self._get_sector_at(pos)
            self.update()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            pos = event.position()
            c = QPointF(self.width() / 2, self.height() / 2)
            dist = math.hypot(pos.x() - c.x(), pos.y() - c.y())

            if self.hub_pressed and dist <= R_HUB:
                self.hub_clicked.emit()
            elif self.pressed_index >= 0 and self.pressed_index == self._get_sector_at(pos):
                act = self.actions[self.pressed_index]
                self.action_selected.emit(act.id)

            self.pressed_index = -1
            self.hub_pressed = False
            self.update()

    def leaveEvent(self, event):
        self.hovered_index = -1
        self.pressed_index = -1
        self.hub_hovered = False
        self.hub_pressed = False
        self.update()

    # ================= Drag & Drop Integration =================
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls() or event.mimeData().hasText():
            event.acceptProposedAction()
            self.hovered_index = self._get_sector_at(event.position())
            self.update()
        else:
            event.ignore()

    def dragMoveEvent(self, event: QDragMoveEvent):
        pos = event.position()
        c = QPointF(self.width() / 2, self.height() / 2)
        dist = math.hypot(pos.x() - c.x(), pos.y() - c.y())

        prev_hover = self.hovered_index
        prev_hub = self.hub_hovered

        if dist <= R_HUB:
            self.hub_hovered = True
            self.hovered_index = -1
        else:
            self.hub_hovered = False
            self.hovered_index = self._get_sector_at(pos)

        if prev_hover != self.hovered_index or prev_hub != self.hub_hovered:
            self.update()

        event.acceptProposedAction()

    def dragLeaveEvent(self, event: QDragLeaveEvent):
        self.hovered_index = -1
        self.hub_hovered = False
        self.update()

    def dropEvent(self, event: QDropEvent):
        target_str = ""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                target_str = urls[0].toLocalFile() or urls[0].toString()
        elif event.mimeData().hasText():
            target_str = event.mimeData().text().strip()

        if target_str:
            if self.hovered_index >= 0:
                act = self.actions[self.hovered_index]
                action_id = act.id
            else:
                action_id = "ai_map"

            self.action_dropped.emit(action_id, target_str)
            event.acceptProposedAction()

        self.hovered_index = -1
        self.hub_hovered = False
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        c = QPointF(self.width() / 2, self.height() / 2)
        n = len(self.actions)

        # 1. Central Hub
        hub_path = QPainterPath()
        r_hub = R_HUB + (2 if self.hub_hovered else 0) - (2 if self.hub_pressed else 0)
        hub_path.addEllipse(c, r_hub, r_hub)

        hub_tint = QColor(48, 28, 70, 245) if self.hub_hovered else QColor(24, 20, 36, 230)
        if self.hub_pressed:
            hub_tint = QColor(70, 35, 105, 255)
        glass.paint_liquid_glass(p, hub_path, tint=hub_tint, rim=True, highlight=1.4 if self.hub_hovered else 1.0)

        # Precise multi-layer typography inside Central Hub (No HTML tags, no overflow)
        # 1a. Lightning Glyph (Top)
        p.setFont(QFont("-apple-system, Segoe UI", 13, QFont.Bold))
        p.setPen(QColor(255, 190, 40) if self.hub_hovered else QColor(255, 220, 80))
        p.drawText(QRectF(c.x() - 20, c.y() - 36, 40, 20), Qt.AlignCenter, "⚡")

        # 1b. Brand Title (Center)
        p.setFont(QFont("-apple-system, Segoe UI", 9, QFont.Bold))
        p.setPen(QColor(255, 255, 255))
        p.drawText(QRectF(c.x() - 46, c.y() - 17, 92, 28), Qt.AlignCenter, "Super\nReverse")

        # 1c. Target File / Status Badge (Bottom)
        p.setFont(QFont("-apple-system, Segoe UI", 7.5, QFont.DemiBold))
        fm = p.fontMetrics()
        raw_target = self.active_target_name
        if raw_target in ("", "Drop Software Here"):
            p.setPen(QColor(148, 163, 184))
            display_text = "Drop Here"
        else:
            p.setPen(QColor(0, 240, 255))
            # Ellipsize the middle so filenames like SuperDrag.apk never overflow
            display_text = fm.elidedText(raw_target, Qt.ElideMiddle, int(2 * (r_hub - 10)))

        p.drawText(QRectF(c.x() - (r_hub - 8), c.y() + 15, 2 * (r_hub - 8), 16), Qt.AlignCenter | Qt.TextSingleLine, display_text)

        # 2. Petals
        for i, act in enumerate(self.actions):
            a0, a1 = angles(n, i)
            is_hover = (i == self.hovered_index)
            is_press = (i == self.pressed_index)

            r_out = R_OUT + (7 if is_hover else 0) - (2 if is_press else 0)
            r_in = R_IN - (2 if is_hover else 0)

            path = sector_path(c, r_in, r_out, a0, a1)

            if is_press:
                tint = QColor(80, 50, 130, 250)
                rim_alpha = 255
                highlight = 1.6
            elif is_hover:
                tint = QColor(50, 38, 85, 240)
                rim_alpha = 240
                highlight = 1.4
            else:
                tint = QColor(20, 18, 30, 180)
                rim_alpha = 140
                highlight = 0.9

            glass.paint_liquid_glass(
                p, path, tint=tint, rim=True, rainbow_alpha=rim_alpha, highlight=highlight
            )

            # Center angle of petal for text
            mid_ang = math.radians((a0 + a1) / 2)
            mid_r = (r_in + r_out) / 2
            tx = c.x() + mid_r * math.cos(mid_ang)
            ty = c.y() - mid_r * math.sin(mid_ang)

            p.save()
            # Draw Glyph
            p.setFont(QFont("-apple-system, Segoe UI", 12))
            p.setPen(QColor(255, 255, 255))
            p.drawText(QRectF(tx - 40, ty - 22, 80, 22), Qt.AlignCenter, act.glyph)

            # Draw Label
            p.setFont(QFont("-apple-system, Segoe UI", 8.5, QFont.Bold if (is_hover or is_press) else QFont.DemiBold))
            p.setPen(QColor(255, 255, 255) if (is_hover or is_press) else QColor(203, 213, 225))
            p.drawText(QRectF(tx - 40, ty + 1, 80, 18), Qt.AlignCenter, act.label)
            p.restore()
