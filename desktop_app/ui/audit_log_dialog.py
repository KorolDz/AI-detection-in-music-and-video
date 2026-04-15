from __future__ import annotations

import json

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QAbstractItemView
    from PySide6.QtWidgets import QDialog
    from PySide6.QtWidgets import QHBoxLayout
    from PySide6.QtWidgets import QLabel
    from PySide6.QtWidgets import QPushButton
    from PySide6.QtWidgets import QSplitter
    from PySide6.QtWidgets import QTableWidget
    from PySide6.QtWidgets import QTableWidgetItem
    from PySide6.QtWidgets import QTextEdit
    from PySide6.QtWidgets import QVBoxLayout
except ImportError as exc:  # pragma: no cover - depends on local env
    raise ImportError("Для запуска desktop-интерфейса необходимо установить PySide6.") from exc

from desktop_app.application.audit_log_service import AuditLogService
from desktop_app.domain import AuditLogEntry


class AuditLogDialog(QDialog):
    def __init__(self, audit_log_service: AuditLogService, parent=None) -> None:  # noqa: ANN001
        super().__init__(parent)
        self._audit_log_service = audit_log_service
        self._entries = self._audit_log_service.list_recent(limit=200)

        self.setWindowTitle("Журнал действий")
        self.resize(1120, 640)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel("Последние пользовательские и системные события", self)
        title.setObjectName("cardTitle")

        self.empty_label = QLabel("Нет записей", self)
        self.empty_label.setObjectName("mutedInfo")
        self.empty_label.setWordWrap(True)

        splitter = QSplitter(Qt.Orientation.Vertical, self)

        self.table = QTableWidget(self)
        self.table.setObjectName("auditTable")
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Время", "Событие", "Уровень", "Сообщение", "ID результата"]
        )
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        self.table.itemSelectionChanged.connect(self._sync_details_panel)

        self.details = QTextEdit(self)
        self.details.setObjectName("auditDetails")
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("")

        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        button_row = QHBoxLayout()
        button_row.addStretch(1)

        close_button = QPushButton("Закрыть", self)
        close_button.setObjectName("secondaryButton")
        close_button.clicked.connect(self.reject)
        button_row.addWidget(close_button)

        layout.addWidget(title)
        layout.addWidget(self.empty_label)
        layout.addWidget(splitter, 1)
        layout.addLayout(button_row)

        self._populate_table()
        self._sync_details_panel()

    def _populate_table(self) -> None:
        self.table.setRowCount(len(self._entries))
        self.empty_label.setVisible(not self._entries)
        self.table.setVisible(bool(self._entries))

        for row_index, entry in enumerate(self._entries):
            values = [
                self._format_datetime(entry.event_time),
                entry.event_type,
                entry.severity,
                entry.message,
                str(entry.result_id) if entry.result_id is not None else "-",
            ]
            for column_index, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, row_index)
                self.table.setItem(row_index, column_index, item)

        if self._entries:
            self.table.resizeColumnsToContents()
            self.table.selectRow(0)

    def _sync_details_panel(self) -> None:
        row_index = self.table.currentRow()
        if row_index < 0 or row_index >= len(self._entries):
            self.details.clear()
            return

        entry = self._entries[row_index]
        self.details.setPlainText(self._format_entry_details(entry))

    def _format_entry_details(self, entry: AuditLogEntry) -> str:
        lines = [
            f"Время события: {self._format_datetime(entry.event_time)}",
            f"Тип события: {entry.event_type}",
            f"Уровень: {entry.severity}",
            f"Сообщение: {entry.message}",
            f"ID результата: {entry.result_id if entry.result_id is not None else '-'}",
            "",
            "Детали:",
            json.dumps(entry.details, ensure_ascii=False, indent=2, sort_keys=True),
        ]
        return "\n".join(lines)

    @staticmethod
    def _format_datetime(value) -> str:  # noqa: ANN001
        if value is None:
            return "-"
        return value.strftime("%Y-%m-%d %H:%M:%S")
