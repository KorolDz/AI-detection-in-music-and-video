from __future__ import annotations


MAIN_WINDOW_STYLESHEET = """
QWidget#windowSurface {
    background: qlineargradient(
        x1: 0, y1: 0, x2: 1, y2: 1,
        stop: 0 #f3ede4,
        stop: 0.48 #e8ede8,
        stop: 1 #dbe6e8
    );
    color: #1c2d33;
}

QFrame#heroCard {
    background: qlineargradient(
        x1: 0, y1: 0, x2: 1, y2: 1,
        stop: 0 #14384d,
        stop: 0.55 #1b4e5a,
        stop: 1 #2b675d
    );
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 22px;
}

QLabel#heroEyebrow {
    color: rgba(239, 228, 202, 0.88);
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
}

QLabel#heroTitle {
    color: #fff8ef;
    font-size: 27px;
    font-weight: 700;
}

QLabel#heroSubtitle {
    color: rgba(244, 248, 246, 0.88);
    font-size: 15px;
    line-height: 1.4;
}

QLabel#heroBadge {
    background-color: rgba(255, 248, 239, 0.12);
    color: #fff6ea;
    border: 1px solid rgba(255, 248, 239, 0.14);
    border-radius: 14px;
    padding: 8px 14px;
    font-size: 13px;
    font-weight: 600;
}

QLabel#heroMeta {
    color: rgba(255, 246, 234, 0.88);
    font-size: 14px;
}

QFrame#card {
    background-color: rgba(255, 252, 247, 0.96);
    border: 1px solid #d7d4cb;
    border-radius: 20px;
}

QFrame#subCard {
    background-color: #f7f4ee;
    border: 1px solid #e3ddd1;
    border-radius: 16px;
}

QLabel#cardTitle {
    color: #173447;
    font-size: 19px;
    font-weight: 700;
}

QLabel#cardSubtitle {
    color: #5e6b72;
    font-size: 15px;
}

QLabel#sectionLabel {
    color: #355260;
    font-size: 13px;
    font-weight: 600;
}

QLabel#mutedInfo {
    color: #61737d;
    font-size: 14px;
}

QLineEdit#filePathEdit {
    background-color: #fcfaf6;
    border: 1px solid #d5d7d1;
    border-radius: 14px;
    padding: 10px 12px;
    min-height: 24px;
    font-size: 14px;
    color: #1d2e36;
    selection-background-color: #365f70;
}

QTextEdit#summaryText,
QTextEdit#auditDetails,
QTextBrowser#reportPreviewBrowser,
QListWidget#detailList,
QTableWidget#historyTable,
QTableWidget#auditTable {
    background-color: #fcfaf6;
    border: 1px solid #d8d7d0;
    border-radius: 16px;
    padding: 8px;
    font-size: 14px;
    color: #24343b;
}

QListWidget#detailList::item {
    border-radius: 10px;
    padding: 8px 10px;
    margin: 2px 0;
}

QListWidget#detailList::item:selected {
    background-color: #dae8ea;
    color: #123a48;
}

QTableWidget#historyTable::item,
QTableWidget#auditTable::item {
    padding: 8px 10px;
}

QTableWidget#historyTable::item:selected,
QTableWidget#auditTable::item:selected {
    background-color: #dae8ea;
    color: #123a48;
}

QPushButton {
    border-radius: 14px;
    padding: 10px 16px;
    min-height: 24px;
    font-size: 14px;
    font-weight: 600;
}

QPushButton#primaryButton {
    background-color: #c56c2d;
    color: #fff8f0;
    border: 1px solid #b76024;
}

QPushButton#primaryButton:hover {
    background-color: #d57837;
}

QPushButton#primaryButton:pressed {
    background-color: #ab5c28;
}

QPushButton#secondaryButton {
    background-color: #eef1ed;
    color: #21414d;
    border: 1px solid #c8d0cb;
}

QPushButton#secondaryButton:hover {
    background-color: #e5ebe6;
}

QPushButton#secondaryButton:pressed {
    background-color: #d8e1db;
}

QPushButton:disabled {
    background-color: #e5e0d6;
    color: #9a9b97;
    border: 1px solid #ddd6c9;
}

QProgressBar#busyProgress {
    min-height: 10px;
    max-height: 10px;
    border: 0;
    border-radius: 5px;
    background-color: #e3ddd2;
}

QProgressBar#busyProgress::chunk {
    border-radius: 5px;
    background-color: #2c6970;
}

QProgressBar#probabilityGauge {
    min-height: 18px;
    max-height: 18px;
    border: 0;
    border-radius: 9px;
    background-color: #e3ddd2;
}

QProgressBar#probabilityGauge::chunk {
    border-radius: 9px;
    background-color: #2c6970;
}

QFrame#metricTile {
    background-color: #f7f3ec;
    border: 1px solid #e1dccc;
    border-radius: 16px;
}

QLabel#probabilityValue {
    color: #173447;
    font-size: 24px;
    font-weight: 700;
}

QLabel#metricCaption {
    color: #62737b;
    font-size: 13px;
    font-weight: 600;
}

QLabel#metricValue {
    color: #173447;
    font-size: 22px;
    font-weight: 700;
}

QLabel#metricValueCompact {
    color: #173447;
    font-size: 14px;
    font-weight: 600;
}

QSplitter::handle {
    background: transparent;
    width: 12px;
}
"""
