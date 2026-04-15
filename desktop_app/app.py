from __future__ import annotations

from dataclasses import dataclass

from desktop_app.application.audit_log_service import AuditLogService
from desktop_app.application.audit_logger import AuditLogger
from desktop_app.application.coordinator import AnalysisCoordinator
from desktop_app.application.file_hash_service import FileHashService
from desktop_app.application.file_loader import FileLoader
from desktop_app.application.history_service import AnalysisHistoryService
from desktop_app.application.local_processing_service import LocalProcessingService
from desktop_app.application.precheck_service import PrecheckService
from desktop_app.application.report_formatter import ReportFormatter
from desktop_app.application.result_integrity_service import ResultIntegrityService
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
    history_service: AnalysisHistoryService
    audit_log_service: AuditLogService
    audit_logger: AuditLogger
    integrity_service: ResultIntegrityService
    db_manager: DatabaseManager
    result_repository: SQLiteResultRepository
    audit_repository: SQLiteAuditLogRepository


def create_app_context(config: AppConfig | None = None) -> AppContext:
    app_config = config or AppConfig.default()
    db_manager = DatabaseManager(app_config.db_path)
    db_manager.initialize()

    formatter = ReportFormatter()
    integrity_service = ResultIntegrityService(app_config.db_path.parent / "integrity.key")
    result_repository = SQLiteResultRepository(db_manager, integrity_service)
    audit_repository = SQLiteAuditLogRepository(db_manager)
    audit_logger = AuditLogger(audit_repository)
    history_service = AnalysisHistoryService(result_repository, audit_logger)
    audit_log_service = AuditLogService(audit_repository, audit_logger)
    secure_file_intake = SecureFileIntakeService(app_config)

    coordinator = AnalysisCoordinator(
        file_loader=FileLoader(app_config),
        file_hash_service=FileHashService(),
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
        history_service=history_service,
        audit_log_service=audit_log_service,
        audit_logger=audit_logger,
        integrity_service=integrity_service,
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
    window = MainWindow(
        coordinator=context.coordinator,
        config=context.config,
        history_service=context.history_service,
        audit_log_service=context.audit_log_service,
        audit_logger=context.audit_logger,
    )
    window.show()
    return app.exec()
