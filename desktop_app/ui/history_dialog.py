from __future__ import annotations

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QAbstractItemView
    from PySide6.QtWidgets import QDialog
    from PySide6.QtWidgets import QHBoxLayout
    from PySide6.QtWidgets import QLabel
    from PySide6.QtWidgets import QPushButton
    from PySide6.QtWidgets import QTableWidget
    from PySide6.QtWidgets import QTableWidgetItem
    from PySide6.QtWidgets import QVBoxLayout
except ImportError as exc:  # pragma: no cover - depends on local env
    raise ImportError("Для запуска desktop-интерфейса необходимо установить PySide6.") from exc

from desktop_app.application.history_service import AnalysisHistoryService


class HistoryDialog(QDialog):
    def __init__(self, history_service: AnalysisHistoryService, parent=None) -> None:  # noqa: ANN001
        super().__init__(parent)
        self._history_service = history_service
        self._entries = self._history_service.list_recent(limit=100)
        self.selected_analysis_id: int | None = None

        self.setWindowTitle("История проверок")
        self.resize(1080, 580)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel("Последние сохраненные результаты анализа", self)
        title.setObjectName("cardTitle")

        self.empty_label = QLabel("Нет записей", self)
        self.empty_label.setObjectName("mutedInfo")
        self.empty_label.setWordWrap(True)

        self.table = QTableWidget(self)
        self.table.setObjectName("historyTable")
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(
            [
                "Дата и время",
                "Имя файла",
                "Тип",
                "Статус",
                "Вероятность",
                "Целостность",
                "SHA-256",
                "ID",
            ]
        )
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        self.table.itemSelectionChanged.connect(self._sync_open_button_state)
        self.table.itemDoubleClicked.connect(self._open_selected_entry)

        button_row = QHBoxLayout()
        button_row.addStretch(1)

        self.open_button = QPushButton("Открыть", self)
        self.open_button.setObjectName("primaryButton")
        self.open_button.clicked.connect(self._open_selected_entry)

        close_button = QPushButton("Закрыть", self)
        close_button.setObjectName("secondaryButton")
        close_button.clicked.connect(self.reject)

        button_row.addWidget(self.open_button)
        button_row.addWidget(close_button)

        layout.addWidget(title)
        layout.addWidget(self.empty_label)
        layout.addWidget(self.table, 1)
        layout.addLayout(button_row)

        self._populate_table()
        self._sync_open_button_state()

    def _populate_table(self) -> None:
        self.table.setRowCount(len(self._entries))
        self.empty_label.setVisible(not self._entries)
        self.table.setVisible(bool(self._entries))

        for row_index, entry in enumerate(self._entries):
            values = [
                self._format_datetime(entry.stored_at),
                entry.file_name,
                entry.media_type,
                entry.display_status,
                f"{entry.probability:.4f}" if entry.probability is not None else "-",
                entry.integrity_status,
                self._short_hash(entry.file_sha256),
                str(entry.analysis_id),
            ]
            for column_index, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, entry.analysis_id)
                self.table.setItem(row_index, column_index, item)

        if self._entries:
            self.table.resizeColumnsToContents()
            self.table.selectRow(0)

    def _sync_open_button_state(self) -> None:
        self.open_button.setEnabled(self.table.currentRow() >= 0 and bool(self._entries))

    def _open_selected_entry(self, *_args) -> None:  # noqa: ANN002
        row_index = self.table.currentRow()
        if row_index < 0 or row_index >= len(self._entries):
            return
        self.selected_analysis_id = self._entries[row_index].analysis_id
        self.accept()

    @staticmethod
    def _short_hash(file_sha256: str | None) -> str:
        if not file_sha256:
            return "-"
        if len(file_sha256) <= 16:
            return file_sha256
        return f"{file_sha256[:16]}..."

    @staticmethod
    def _format_datetime(value) -> str:  # noqa: ANN001
        if value is None:
            return "-"
        return value.strftime("%Y-%m-%d %H:%M:%S")
