from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from media_security.core.models import Finding, ScanReport, Severity

SEVERITY_ORDER = {
    Severity.HIGH: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
}

SEVERITY_LABELS = {
    Severity.HIGH: "Высокий риск",
    Severity.WARNING: "Предупреждение",
    Severity.INFO: "Информация",
}

VERDICT_LABELS = {
    "pass": "Пройдено",
    "warning": "Требует внимания",
    "fail": "Подозрительно",
}

RISK_LABELS = {
    "low": "Низкий",
    "medium": "Средний",
    "high": "Высокий",
    "critical": "Критический",
}

SPLICE_STATUS_LABELS = {
    "clean": "Чисто",
    "suspicious": "Подозрительно",
    "unavailable": "Недоступно",
    "none": "Совпадений нет",
    "aligned": "Совпадения найдены",
}

MODALITY_LABELS = {
    "audio": "Аудио",
    "video": "Видео",
    "video_audio_track": "Аудиодорожка видео",
}

DETAIL_KEY_LABELS = {
    "supported_extensions": "Поддерживаемые расширения",
    "expected_mime": "Ожидаемые MIME-типы",
    "mime_type": "MIME-тип",
    "extension": "Расширение",
    "detected_format": "Определённый формат",
    "reason": "Причина",
    "markers": "Маркеры",
    "match_count": "Совпадений",
    "error": "Ошибка",
    "sources": "Источники",
    "modalities": "Модули",
    "missing_dependencies": "Недостающие зависимости",
    "value": "Значение",
    "values": "Значения",
    "candidate_count": "Кандидатов",
    "peak_confidence": "Пиковая уверенность",
    "top_candidates": "Ключевые кандидаты",
    "content_profile": "Профиль анализа",
    "scene_transition_count": "Проверено переходов",
}

MAX_DETAIL_PARTS = 3
MAX_LIST_ITEMS = 3
MAX_CANDIDATES_PER_MODALITY = 5


def render_markdown_report(target: str | Path, reports: list[ScanReport]) -> str:
    resolved_target = _resolve_path_text(target)
    generated_at = datetime.now(tz=UTC).isoformat()
    ordered_reports = _sort_reports(reports)

    lines = [
        "# Отчёт по анализу медиафайлов",
        "",
        f"- Сформирован: `{generated_at}`",
        f"- Цель анализа: `{resolved_target}`",
        f"- Проверено файлов: {len(ordered_reports)}",
        "",
    ]

    if len(ordered_reports) > 1:
        lines.extend(_render_summary_section(ordered_reports))
        lines.append("")

    for index, report in enumerate(ordered_reports, start=1):
        lines.extend(
            _render_report_section(
                report=report,
                multiple=len(ordered_reports) > 1,
                index=index,
            )
        )
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def write_markdown_report(output_path: Path, target: str | Path, reports: list[ScanReport]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_markdown_report(target=target, reports=reports),
        encoding="utf-8",
    )


def _render_summary_section(reports: list[ScanReport]) -> list[str]:
    total = len(reports)
    passed = sum(1 for report in reports if report.verdict == "pass")
    warnings = sum(1 for report in reports if report.verdict == "warning")
    failed = sum(1 for report in reports if report.verdict == "fail")
    suspicious = [report for report in reports if report.verdict != "pass"]

    lines = [
        "## Общая сводка",
        "",
        f"- Всего файлов: {total}",
        f"- Без замечаний: {passed}",
        f"- Требуют внимания: {warnings}",
        f"- Подозрительных: {failed}",
        "",
        "## Подозрительные файлы",
        "",
    ]

    if not suspicious:
        lines.append("- Подозрительных файлов не обнаружено.")
        return lines

    for report in suspicious:
        label = VERDICT_LABELS.get(report.verdict, report.verdict)
        score = f"{report.trust_score}/100"
        lines.append(
            f"- `{_resolve_path_text(report.file)}`: {label}, риск {RISK_LABELS.get(report.risk_level, report.risk_level)}, trust score {score}"
        )
    return lines


def _render_report_section(report: ScanReport, multiple: bool, index: int) -> list[str]:
    report_path = _resolve_path_text(report.file)
    title = f"## Файл {index}: `{Path(report.file).name}`" if multiple else "## Итог анализа"
    lines = [
        title,
        "",
        f"- Путь: `{report_path}`",
        "",
        "### Статус",
        "",
        f"- Поддерживается: {_yes_no(report.supported)}",
        f"- Итог: {VERDICT_LABELS.get(report.verdict, report.verdict)}",
        f"- Уровень риска: {RISK_LABELS.get(report.risk_level, report.risk_level)}",
        f"- Trust score: {report.trust_score}/100",
        f"- ID записи в истории: {report.scan_id if report.scan_id is not None else 'Недоступно'}",
        "",
    ]

    if not report.supported:
        lines.extend(
            [
                "### Ключевые проблемы",
                "",
                "- Файл не соответствует поддерживаемым форматам текущего модуля.",
                "",
                "### Рекомендация",
                "",
                "- Используйте поддерживаемый формат (`wav`, `mp3`, `mp4`, `avi`, `mov`) и повторите анализ.",
            ]
        )
        return lines

    lines.extend(_render_findings_section(report.findings))
    lines.append("")
    lines.extend(_render_metadata_section(report))
    lines.append("")
    lines.extend(_render_forensics_section(report))
    lines.append("")
    lines.extend(_render_splice_section(report))
    lines.append("")
    lines.extend(_render_recommendation_section(report))
    return lines


def _render_findings_section(findings: list[Finding]) -> list[str]:
    lines = ["### Ключевые проблемы", ""]
    if not findings:
        lines.append("- Существенных проблем не обнаружено.")
        return lines

    ordered = sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.code))
    for severity in (Severity.HIGH, Severity.WARNING, Severity.INFO):
        severity_findings = [item for item in ordered if item.severity == severity]
        if not severity_findings:
            continue
        lines.append(f"#### {SEVERITY_LABELS[severity]}")
        lines.append("")
        for finding in severity_findings:
            details_text = _summarize_details(finding.details)
            suffix = f"; {details_text}" if details_text else ""
            lines.append(f"- `{finding.code}`: {finding.message}{suffix}")
        lines.append("")

    if lines[-1] == "":
        lines.pop()
    return lines


def _render_metadata_section(report: ScanReport) -> list[str]:
    metadata = report.metadata
    if metadata is None:
        return ["### Основные метаданные", "", "- Недоступно."]

    timestamps = metadata.timestamps_utc or {}
    detected_format = metadata.detected_format or metadata.extension or "Недоступно"
    sha256_hash = metadata.hashes.get("sha256", "Недоступно")

    return [
        "### Основные метаданные",
        "",
        f"- Формат: `{str(detected_format).upper()}`",
        f"- MIME-тип: {_display_value(metadata.mime_type)}",
        f"- Размер: {_format_size(metadata.size_bytes)}",
        f"- SHA-256: `{sha256_hash}`",
        f"- Создан: {_display_value(timestamps.get('created_at'))}",
        f"- Изменён: {_display_value(timestamps.get('modified_at'))}",
        f"- Последний доступ: {_display_value(timestamps.get('accessed_at'))}",
    ]


def _render_forensics_section(report: ScanReport) -> list[str]:
    metadata = report.metadata
    if metadata is None:
        return ["### Криминалистические признаки", "", "- Недоступно."]

    technical = metadata.technical if isinstance(metadata.technical, dict) else {}
    metadata_hints = technical.get("metadata_hints")
    metadata_hints = metadata_hints if isinstance(metadata_hints, dict) else {}

    exiftool = technical.get("exiftool")
    exiftool = exiftool if isinstance(exiftool, dict) else {}
    high_value = exiftool.get("high_value")
    high_value = high_value if isinstance(high_value, dict) else {}

    forensic = technical.get("metadata_forensics")
    forensic = forensic if isinstance(forensic, dict) else {}
    xmp = forensic.get("xmp")
    xmp = xmp if isinstance(xmp, dict) else {}
    timeline = forensic.get("metadata_edit_timeline")
    timeline = timeline if isinstance(timeline, dict) else {}

    device = _best_text(
        metadata_hints.get("source_device"),
        high_value.get("source_device"),
        _join_nonempty(metadata_hints.get("device_make"), metadata_hints.get("device_model")),
        _join_nonempty(high_value.get("device_make"), high_value.get("device_model")),
    )
    model = _best_text(metadata_hints.get("device_model"), high_value.get("device_model"))
    software = _combine_software_values(metadata_hints, high_value)
    recorded_at = _best_text(metadata_hints.get("recorded_at"), high_value.get("recorded_at"))
    location = _best_text(metadata_hints.get("location"), high_value.get("gps_coordinates"))
    sources = forensic.get("sources_present")
    editing_markers = forensic.get("editing_markers")
    hardware_present = forensic.get("hardware_markers_present")
    xmp_present = xmp.get("present")

    lines = [
        "### Криминалистические признаки",
        "",
        f"- Источники метаданных: {_format_scalar_list(sources, unavailable='Недоступно')}",
        f"- Устройство: {_display_value(device)}",
    ]

    if model and device and model.lower() not in device.lower():
        lines.append(f"- Модель: {_display_value(model)}")

    lines.extend(
        [
            f"- ПО / ОС: {_display_value(software)}",
            f"- Время записи: {_display_value(recorded_at)}",
            f"- Координаты: {_display_value(location)}",
            f"- Аппаратные метки: {_format_hardware_presence(hardware_present)}",
            f"- XMP-метаданные: {_format_presence_flag(xmp_present)}",
            f"- Следы редактирования в метаданных: {_format_editing_markers(editing_markers)}",
            f"- Изменение метаданных после записи: {_format_timeline(timeline)}",
        ]
    )
    return lines


def _render_splice_section(report: ScanReport) -> list[str]:
    metadata = report.metadata
    if metadata is None:
        return ["### Склейки и швы", "", "- Недоступно."]

    technical = metadata.technical if isinstance(metadata.technical, dict) else {}
    splice = technical.get("splice_analysis")
    if not isinstance(splice, dict):
        return ["### Склейки и швы", "", "- Недоступно."]

    summary = splice.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    lines = [
        "### Склейки и швы",
        "",
        f"- Общий статус: {SPLICE_STATUS_LABELS.get(str(splice.get('status', 'unavailable')), 'Недоступно')}",
        f"- Найдено кандидатов: {summary.get('candidate_count', 0)}",
        f"- Пиковая уверенность: {_format_confidence(summary.get('peak_confidence'))}",
        f"- Ключевые таймкоды: {_format_timestamp_list(summary.get('top_timestamps_sec'))}",
    ]

    for modality_key in ("audio", "video", "video_audio_track"):
        lines.append("")
        lines.extend(_render_splice_modality(modality_key, splice.get(modality_key)))

    correlation = splice.get("correlation")
    lines.append("")
    lines.extend(_render_correlation(correlation))
    return lines


def _render_splice_modality(modality_key: str, modality: object) -> list[str]:
    label = MODALITY_LABELS[modality_key]
    lines = [f"#### {label}", ""]
    if not isinstance(modality, dict):
        lines.append("- Недоступно.")
        return lines

    status = str(modality.get("status", "unavailable"))
    reason = modality.get("reason")
    lines.append(f"- Статус: {SPLICE_STATUS_LABELS.get(status, 'Недоступно')}")
    if status == "unavailable":
        if reason:
            lines.append(f"- Причина: {_translate_splice_reason(reason)}")
        missing_dependencies = modality.get("missing_dependencies")
        if isinstance(missing_dependencies, list) and missing_dependencies:
            lines.append(f"- Не хватает зависимостей: {', '.join(str(item) for item in missing_dependencies)}")
        return lines

    lines.append(f"- Кандидатов: {modality.get('candidate_count', 0)}")
    lines.append(f"- Пиковая уверенность: {_format_confidence(modality.get('peak_confidence'))}")
    content_profile = modality.get("content_profile")
    if content_profile:
        lines.append(f"- Профиль: {_format_content_profile(content_profile)}")
    scene_transition_count = modality.get("scene_transition_count")
    if isinstance(scene_transition_count, int):
        lines.append(f"- Проверено переходов: {scene_transition_count}")

    candidates = modality.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        lines.append("- Подозрительных швов не обнаружено.")
        return lines

    lines.append(f"- Ключевые точки: {_format_candidate_list(candidates)}")
    return lines


def _render_correlation(correlation: object) -> list[str]:
    lines = ["#### Корреляция видео и аудиодорожки", ""]
    if not isinstance(correlation, dict):
        lines.append("- Недоступно.")
        return lines

    status = str(correlation.get("status", "unavailable"))
    lines.append(f"- Статус: {SPLICE_STATUS_LABELS.get(status, 'Недоступно')}")
    lines.append(f"- Совпадений: {correlation.get('match_count', 0)}")

    matches = correlation.get("matches")
    if not isinstance(matches, list) or not matches:
        lines.append("- Согласованных швов не найдено.")
        return lines

    rendered_matches: list[str] = []
    for match in matches[:MAX_CANDIDATES_PER_MODALITY]:
        if not isinstance(match, dict):
            continue
        rendered_matches.append(
            f"{_format_timestamp(match.get('video_timestamp_sec'))} / {_format_timestamp(match.get('audio_timestamp_sec'))} (delta {_format_timestamp(match.get('delta_sec'))})"
        )
    lines.append(f"- Совпавшие точки: {', '.join(rendered_matches) if rendered_matches else 'Недоступно'}")
    return lines


def _render_recommendation_section(report: ScanReport) -> list[str]:
    return [
        "### Рекомендация",
        "",
        f"- {_recommendation_text(report)}",
    ]


def _recommendation_text(report: ScanReport) -> str:
    if not report.supported:
        return "Формат не поддерживается текущим модулем, поэтому нужен повторный анализ после конвертации в поддерживаемый формат."
    if report.verdict == "pass":
        return "Существенных признаков подделки по КБ-проверкам не обнаружено, файл можно использовать при обычной проверке."
    if report.verdict == "warning":
        return "Файл требует ручной проверки: найдены признаки редактирования или аномалии, которые стоит перепроверить отдельно."
    return "Файл выглядит подозрительно, рекомендуется ручная проверка в изолированной среде и дополнительный анализ."


def _summarize_details(details: dict[str, Any]) -> str:
    if not details:
        return ""

    parts: list[str] = []
    for key, value in details.items():
        if key == "reason":
            rendered = _translate_splice_reason(value)
        elif key == "modalities" and isinstance(value, list):
            rendered = ", ".join(MODALITY_LABELS.get(str(item), str(item)) for item in value)
        elif key == "top_candidates" and isinstance(value, list):
            rendered = _format_candidate_list(value)
        elif key == "matches" and isinstance(value, list):
            rendered = _format_match_list(value)
        else:
            rendered = _format_detail_value(value)
        if not rendered:
            continue
        label = DETAIL_KEY_LABELS.get(key, _humanize_key(key))
        parts.append(f"{label}: {rendered}")
        if len(parts) >= MAX_DETAIL_PARTS:
            break

    return "; ".join(parts)


def _format_detail_value(value: object) -> str:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, bool):
        return _yes_no(value)
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return _format_scalar_list(value, unavailable="")
    if isinstance(value, dict):
        parts: list[str] = []
        for subkey, subvalue in value.items():
            rendered = _format_detail_value(subvalue)
            if not rendered:
                continue
            parts.append(f"{_humanize_key(subkey)}: {rendered}")
            if len(parts) >= 2:
                break
        return "; ".join(parts)
    return str(value)


def _format_match_list(matches: list[object]) -> str:
    rendered: list[str] = []
    for match in matches[:MAX_CANDIDATES_PER_MODALITY]:
        if not isinstance(match, dict):
            continue
        video_time = _format_timestamp(match.get("video_timestamp_sec"))
        audio_time = _format_timestamp(match.get("audio_timestamp_sec"))
        delta = _format_timestamp(match.get("delta_sec"))
        rendered.append(f"{video_time} / {audio_time} (delta {delta})")
    return ", ".join(rendered) if rendered else ""


def _sort_reports(reports: list[ScanReport]) -> list[ScanReport]:
    verdict_rank = {"fail": 0, "warning": 1, "pass": 2}
    return sorted(
        reports,
        key=lambda report: (
            verdict_rank.get(report.verdict, 99),
            _resolve_path_text(report.file).lower(),
        ),
    )


def _resolve_path_text(value: str | Path) -> str:
    path = Path(value).expanduser()
    return str(path.resolve(strict=False))


def _display_value(value: object) -> str:
    if value in (None, "", [], {}):
        return "Недоступно"
    return str(value)


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} байт"
    units = ["KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    unit = units[0]
    for unit in units:
        size /= 1024.0
        if size < 1024 or unit == units[-1]:
            break
    return f"{size:.2f} {unit} ({size_bytes} байт)"


def _yes_no(value: bool) -> str:
    return "Да" if value else "Нет"


def _best_text(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _join_nonempty(*values: object) -> str | None:
    parts = [str(value).strip() for value in values if isinstance(value, str) and value.strip()]
    if not parts:
        return None
    return " ".join(parts)


def _combine_software_values(metadata_hints: dict[str, object], high_value: dict[str, object]) -> str | None:
    values: list[str] = []
    for candidate in (
        metadata_hints.get("editing_software"),
        metadata_hints.get("os_version"),
        high_value.get("software_version"),
        high_value.get("os_version"),
    ):
        if isinstance(candidate, str) and candidate.strip():
            text = candidate.strip()
            if text not in values:
                values.append(text)
    return " / ".join(values) if values else None


def _format_scalar_list(value: object, unavailable: str = "Не обнаружено") -> str:
    if not isinstance(value, list) or not value:
        return unavailable
    items = [str(item) for item in value[:MAX_LIST_ITEMS] if item not in (None, "")]
    if not items:
        return unavailable
    if len(value) > len(items):
        items.append(f"и ещё {len(value) - len(items)}")
    return ", ".join(items)


def _format_hardware_presence(value: object) -> str:
    if isinstance(value, bool):
        return "Обнаружены" if value else "Не найдены"
    return "Недоступно"


def _format_presence_flag(value: object) -> str:
    if isinstance(value, bool):
        return "Есть" if value else "Не обнаружены"
    return "Недоступно"


def _format_editing_markers(value: object) -> str:
    if not isinstance(value, list):
        return "Недоступно"
    if not value:
        return "Не обнаружены"
    markers = [str(item) for item in value[:MAX_LIST_ITEMS]]
    if len(value) > len(markers):
        markers.append(f"и ещё {len(value) - len(markers)}")
    return "; ".join(markers)


def _format_timeline(timeline: dict[str, object]) -> str:
    status = timeline.get("status")
    if status == "modified_after_recording":
        modified_at = _display_value(timeline.get("modified_at_utc"))
        return f"Да, метаданные изменялись после записи (последнее изменение: {modified_at})"
    if timeline:
        return "Дополнительная временная информация доступна."
    return "Не обнаружено"


def _format_confidence(value: object) -> str:
    if value in (None, "", [], {}):
        return "Недоступно"
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{numeric:.0%}"


def _format_timestamp_list(value: object) -> str:
    if not isinstance(value, list) or not value:
        return "Не обнаружены"
    return ", ".join(_format_timestamp(item) for item in value[:MAX_CANDIDATES_PER_MODALITY])


def _format_candidate_list(candidates: list[object]) -> str:
    rendered: list[str] = []
    for candidate in candidates[:MAX_CANDIDATES_PER_MODALITY]:
        if not isinstance(candidate, dict):
            continue
        timestamp = _format_timestamp(candidate.get("timestamp_sec"))
        confidence = _format_confidence(candidate.get("confidence"))
        reasons = _format_candidate_reasons(candidate.get("reasons"), candidate.get("signals"))
        suffix = f"; {reasons}" if reasons else ""
        rendered.append(f"{timestamp} ({confidence}{suffix})")
    return ", ".join(rendered) if rendered else "Недоступно"


def _format_timestamp(value: object) -> str:
    try:
        if value is None:
            return "Недоступно"
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{numeric:.3f} с"


def _translate_splice_reason(value: object) -> str:
    reason = str(value)
    mapping = {
        "ffmpeg_not_available": "ffmpeg недоступен",
        "analysis_error": "ошибка анализа",
        "no_audio_stream": "у видео нет аудиодорожки",
        "decode_failed": "не удалось декодировать поток",
        "dimensions_unavailable": "не удалось определить размер кадра",
        "missing_audio_dependencies": "не хватает numpy или pydub",
        "missing_video_dependencies": "не хватает numpy или PySceneDetect",
        "scene_detection_failed": "не удалось выделить кандидаты смен сцен",
    }
    return mapping.get(reason, reason)


def _format_content_profile(value: object) -> str:
    mapping = {
        "speech_or_general": "речь или обычная запись",
        "music_like": "музыкальный/плотный микс",
    }
    text = str(value)
    return mapping.get(text, text)


def _format_candidate_reasons(reasons: object, signals: object) -> str:
    if isinstance(reasons, list) and reasons:
        return ", ".join(str(item) for item in reasons[:3])
    if not isinstance(signals, dict):
        return ""
    ordered = sorted(
        ((str(name), float(value)) for name, value in signals.items() if isinstance(value, (int, float))),
        key=lambda item: item[1],
        reverse=True,
    )
    labels = [_humanize_signal_name(name) for name, value in ordered[:3] if value > 0]
    return ", ".join(labels)


def _humanize_signal_name(value: str) -> str:
    mapping = {
        "rms_jump": "скачок громкости",
        "spectral_flux": "резкий спектральный переход",
        "onset_jump": "скачок onset",
        "mfcc_distance": "смена тембра",
        "spectral_centroid_shift": "сдвиг спектрального центра",
        "spectral_bandwidth_shift": "сдвиг ширины спектра",
        "silence_boundary": "граница паузы",
        "scene_score": "резкая смена сцены",
        "freeze_near_boundary": "freeze рядом с переходом",
        "black_or_dark_transition": "тёмный кадр на границе",
        "short_shot_gap": "короткий фрагмент",
        "audio_track_alignment": "совпадение с аудиодорожкой",
    }
    return mapping.get(value, _humanize_key(value))


def _humanize_key(value: str) -> str:
    return value.replace("_", " ").strip().capitalize()
