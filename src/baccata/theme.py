"""Baccata's look: Taxus baccata, the yew. A dark ground, the deep green of
the needles, the red of the arils. Fusion style on every platform so the
window is the same window on macOS, Windows and Linux; the palette does the
rest, so widgets stay plain Qt widgets (no stylesheet theme to fight).
"""
from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (QColor, QIcon, QPainter,
                           QPainterPath, QPalette, QPen, QPixmap)
from PySide6.QtWidgets import QApplication

GREEN = QColor('#4f8f3e')        # needle: selection, focus, links
GREEN_DIM = QColor('#2f5a28')    # needle in shade: inactive selection
RED = QColor('#d33a2c')          # aril: errors, destructive, unsaved
GROUND = QColor('#1c211d')       # window
DEEP = QColor('#0f120f')         # list/field base
RAISED = QColor('#2a312b')       # buttons, tooltips
INK = QColor('#d8ddd5')          # text
INK_DIM = QColor('#737d74')      # disabled text, placeholders, captions


def palette():
    p = QPalette()
    p.setColor(QPalette.Window, GROUND)
    p.setColor(QPalette.Base, DEEP)
    p.setColor(QPalette.AlternateBase, QColor('#151915'))
    p.setColor(QPalette.Button, RAISED)
    p.setColor(QPalette.ToolTipBase, RAISED)
    p.setColor(QPalette.Highlight, GREEN)
    p.setColor(QPalette.Inactive, QPalette.Highlight, GREEN_DIM)
    p.setColor(QPalette.HighlightedText, QColor('#eef2ea'))
    p.setColor(QPalette.Link, QColor('#8fcf7a'))
    p.setColor(QPalette.LinkVisited, QColor('#7ab668'))
    p.setColor(QPalette.BrightText, RED)
    p.setColor(QPalette.PlaceholderText, INK_DIM)
    # Fusion's bevels come from these
    p.setColor(QPalette.Light, QColor('#3a433b'))
    p.setColor(QPalette.Midlight, QColor('#313932'))
    p.setColor(QPalette.Mid, QColor('#404b42'))
    p.setColor(QPalette.Dark, QColor('#0a0c0a'))
    p.setColor(QPalette.Shadow, QColor('#000000'))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText,
                 QPalette.ToolTipText):
        p.setColor(role, INK)
        p.setColor(QPalette.Disabled, role, INK_DIM)
    p.setColor(QPalette.Disabled, QPalette.Base, QColor('#141814'))
    p.setColor(QPalette.Disabled, QPalette.Button, QColor('#1e2320'))
    p.setColor(QPalette.Disabled, QPalette.Highlight, GREEN_DIM)
    return p


# What the palette cannot say. Kept to the few things Fusion gets wrong on a
# dark ground; widgets are otherwise unstyled.
STYLE = f"""
QToolTip {{ border: 1px solid {GREEN.name()}; padding: 3px; }}
QSplitter::handle {{ background: {GROUND.name()}; }}
QToolBar {{ padding: 1px 4px; spacing: 4px; border-bottom: 1px solid #404b42; }}
QToolBar QComboBox {{ padding: 1px 4px; }}
QTabWidget::pane {{ border-top: 1px solid #404b42; }}
QTabBar::tab {{ padding: 4px 12px; }}
QAbstractScrollArea {{ border: 1px solid #404b42; }}
QTreeView::item {{ padding: 2px 4px; }}
QHeaderView::section {{ background: {RAISED.name()}; border: none;
    border-right: 1px solid {GROUND.name()};
    border-bottom: 1px solid {GROUND.name()}; padding: 4px 6px; }}
QStatusBar {{ border-top: 1px solid {RAISED.name()}; }}
"""





def apply(app):
    app.setStyle('Fusion')
    app.setPalette(palette())
    app.setStyleSheet(STYLE)
    app.setWindowIcon(icon())


# ---- the twig -------------------------------------------------------------

def paint_twig(p, size, ground=True):
    """Yew twig on a QPainter: a stem up the diagonal, flat paired needles,
    one aril. `size` is the square it fills; `ground` paints the dark
    rounded square behind it (the app icon), else the twig alone."""
    s = size / 100.0                    # design units: 100 x 100
    p.setRenderHint(QPainter.Antialiasing)
    if ground:
        p.setPen(Qt.NoPen)
        p.setBrush(GROUND)
        p.drawRoundedRect(QRectF(0, 0, size, size), 22 * s, 22 * s)

    def twig(stem, ts, width, ln0, ln1, half):
        """A stem path with needle pairs at fractions `ts`; needle length
        runs ln0 -> ln1 base to tip, `half` is the needle half-width."""
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(QColor('#6d5a3a'), width * s, Qt.SolidLine, Qt.RoundCap))
        p.drawPath(stem)
        p.setPen(QPen(QColor('#1f3a1b'), 1.2 * s))
        p.setBrush(GREEN)
        for t in ts:
            pt = stem.pointAtPercent(t)
            ang = stem.angleAtPercent(t)           # degrees, ccw
            ln = (ln0 + (ln1 - ln0) * t) * s
            for side in (1, -1):
                p.save()
                p.translate(pt)
                p.rotate(-ang + side * 68)
                needle = QPainterPath(QPointF(0, 0))
                needle.quadTo(QPointF(ln * 0.5, -half * s), QPointF(ln, 0))
                needle.quadTo(QPointF(ln * 0.5, half * s), QPointF(0, 0))
                p.drawPath(needle)
                p.restore()

    # main stem: bottom-left to top-right, slightly bowed; two side twigs
    # branch off it -- a bus line with its branches
    stem = QPainterPath(QPointF(20 * s, 78 * s))
    stem.quadTo(QPointF(50 * s, 52 * s), QPointF(80 * s, 14 * s))
    a = stem.pointAtPercent(0.2)
    left = QPainterPath(a)
    left.quadTo(a + QPointF(-1 * s, -19 * s), a + QPointF(-6 * s, -37 * s))   # ~55 deg off the stem
    b = stem.pointAtPercent(0.42)
    right = QPainterPath(b)
    right.quadTo(b + QPointF(19 * s, 3 * s), b + QPointF(39 * s, 9 * s))
    side_ts = (0.3, 0.55, 0.8, 0.98)
    twig(left, side_ts, 2.8, 15, 9, 2.8)
    twig(right, side_ts, 2.8, 15, 9, 2.8)

    twig(stem, (0.08, 0.2, 0.32, 0.44, 0.56, 0.68, 0.8, 0.9), 4.5, 30, 14, 4.2)

    # aril: on the main twig between the forks, open end pointing away
    # from it with the seed showing
    c = stem.pointAtPercent(0.31) + QPointF(-1 * s, 6 * s)
    r = 11.5 * s
    p.setPen(QPen(QColor('#7a1f17'), 1.2 * s))
    p.setBrush(RED)
    p.drawEllipse(c, r, r)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor('#ff8f80'))                # highlight
    p.drawEllipse(c + QPointF(-3.5 * s, -4 * s), 2.8 * s, 2 * s)
    p.setBrush(QColor('#3b241c'))                # the cup opening + seed
    p.drawEllipse(c + QPointF(-2 * s, 5.5 * s), 4.2 * s, 3.2 * s)



def pixmap(size, ground=True):
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    paint_twig(p, size, ground)
    p.end()
    return pm


def icon():
    ic = QIcon()
    for n in (16, 32, 64, 128, 256, 512):
        ic.addPixmap(pixmap(n))
    return ic
