from media_security.core.metadata_forensics import analyze_metadata_forensics


def test_metadata_forensics_detects_cross_source_conflicts() -> None:
    technical = {
        "embedded_tags": {
            "udta.auth": "Galaxy S25 Ultra",
            "udta.mdln": "SM-S938B",
        },
        "ffprobe": {
            "format_tags": {
                "creation_time": "2026-04-01T10:52:28Z",
                "com.apple.quicktime.location.ISO6709": "+43.7694+011.2555+048.329/",
                "com.apple.quicktime.make": "Samsung",
                "com.apple.quicktime.model": "SM-S938B",
            },
            "stream_tags": {},
        },
        "exiftool": {
            "tags": {
                "Author": "iPhone 15 Pro",
                "Model": "A3102",
                "CreateDate": "2026:04:02 13:52:28+03:00",
                "GPSPosition": "40 deg 0' 0.00\" N, 10 deg 0' 0.00\" E",
            }
        },
    }

    findings = analyze_metadata_forensics("mp4", technical)
    codes = {finding.code for finding in findings}

    assert "METADATA_DEVICE_CONFLICT" in codes
    assert "METADATA_TIMESTAMP_CONFLICT" in codes
    assert "METADATA_LOCATION_CONFLICT" in codes

    forensic_summary = technical["metadata_forensics"]
    assert forensic_summary["hardware_markers_present"] is True
    assert forensic_summary["cross_checks"]["device"]["status"] == "conflict"


def test_metadata_forensics_flags_xmp_editing_and_missing_hardware_tags() -> None:
    technical = {
        "exiftool": {
            "tags": {
                "CreatorTool": "Adobe Premiere Pro 24.0",
                "HistorySoftwareAgent": "Adobe Premiere Pro",
                "MetadataDate": "2026:04:02T10:00:00Z",
                "CreateDate": "2026:04:01T10:00:00Z",
                "ModifyDate": "2026:04:02T10:00:00Z",
            }
        }
    }

    findings = analyze_metadata_forensics("mp4", technical)
    codes = {finding.code for finding in findings}

    assert "EDITING_SOFTWARE_METADATA_MARKER" in codes
    assert "XMP_METADATA_PRESENT" in codes
    assert "HARDWARE_TAGS_MISSING" in codes
    assert "METADATA_MODIFIED_AFTER_RECORDING" in codes

    forensic_summary = technical["metadata_forensics"]
    assert forensic_summary["xmp"]["present"] is True
    assert forensic_summary["metadata_edit_timeline"]["status"] == "modified_after_recording"
