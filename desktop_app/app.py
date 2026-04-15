from __future__ import annotations

from dataclasses import dataclass

from desktop_app.application.audit_logger import AuditLogger
from desktop_app.application.coordinator import AnalysisCoordinator
from desktop_app.application.file_loader import FileLoader
from desktop_app.application.local_processing_service import LocalProcessingService
from desktop_app.application.precheck_service import PrecheckService
from desktop_app.application.report_formatter import ReportFormatter
from desktop_app.application.secure_file_intake import SecureFileIntakeService
from desktop_app.config import AppConfig
from desktop_app.infrastructure import DatabaseManager
from desktop_app.infrastructure import SQLiteAuditLogRepository
from desktop_app.infrastructure import SQLiteResultRepository
from desktop_app.infrastructure import VideoAnalyzerAdapter


@dataclass(slots=True)
class AppContext:
    config: AppConfig
    coordinator: AnalysisCoordinator
    db_manager: DatabaseManager
    result_repository: SQLiteResultRepository
    audit_repository: SQLiteAuditLogRepository


def create_app_context(config: AppConfig | None = None) -> AppContext:
    app_config = config or AppConfig.default()
    db_manager = DatabaseManager(app_config.db_path)
    db_manager.initialize()

    formatter = ReportFormatter()
    result_repository = SQLiteResultRepository(db_manager)
    audit_repository = SQLiteAuditLogRepository(db_manager)
    audit_logger = AuditLogger(audit_repository)
    secure_file_intake = SecureFileIntakeService(app_config)

    coordinator = AnalysisCoordinator(
        file_loader=FileLoader(app_config),
        local_processing_service=LocalProcessingService(secure_file_intake),
        precheck_service=PrecheckService(app_config),
        analyzer_gateway=VideoAnalyzerAdapter(default_threshold=app_config.model_threshold),
        result_repository=result_repository,
        audit_logger=audit_logger,
        report_formatter=formatter,
    )

    return AppContext(
        config=app_config,
        coordinator=coordinator,
        db_manager=db_manager,
        result_repository=result_repository,
        audit_repository=audit_repository,
    )


def run_app() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:  # pragma: no cover - depends on local env
        raise ImportError(
            "Для запуска desktop-интерфейса необходимо установить PySide6."
        ) from exc

    from desktop_app.ui.main_window import MainWindow

    context = create_app_context()
    app = QApplication.instance() or QApplication([])
    window = MainWindow(coordinator=context.coordinator, config=context.config)
    window.show()
    return app.exec()
