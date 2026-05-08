import logging
from pathlib import Path
from typing import Any

import yaml

from models import AppConfig, CertificateMapping, CertificatesConfig


logger = logging.getLogger(__name__)


def _require_dict(data: Any, name: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError(f"{name} must be a mapping")
    return data


def _require_str(data: dict[str, Any], key: str, name: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name}.{key} must be a non-empty string")
    return value.strip()


def _optional_str(data: dict[str, Any], key: str, name: str) -> str:
    value = data.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{name}.{key} must be a string")
    return value.strip()


def read_config(path: str | Path = "./config.yaml") -> AppConfig:
    """
    Read yaml configuration file and return config object.
    """
    config_path = Path(path)
    logger.info("Reading config file: %s", config_path)

    try:
        with config_path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

        if data is None:
            raise ValueError("Config file is empty")

        data = _require_dict(data, "config")
        logger.debug("Config file parsed successfully: %s", config_path)

        cert_data = _require_dict(data.get("certificates"), "certificates")
        mappings_data = cert_data.get("mappings", [])

        if not isinstance(mappings_data, list):
            raise ValueError("certificates.mappings must be a list")

        logger.info("Found %d certificate mapping(s)", len(mappings_data))

        mappings: list[CertificateMapping] = []

        for index, item in enumerate(mappings_data, start=1):
            item = _require_dict(item, f"certificates.mappings[{index}]")
            zip_name = _require_str(item, "zip_name", f"certificates.mappings[{index}]")
            target_file_path = _optional_str(
                item,
                "target_file_path",
                f"certificates.mappings[{index}]",
            )
            target_file_dir = _optional_str(
                item,
                "target_file_dir",
                f"certificates.mappings[{index}]",
            )

            if not target_file_path and not target_file_dir:
                raise ValueError(
                    f"certificates.mappings[{index}] must define target_file_dir "
                    "or target_file_path"
                )

            logger.debug(
                "Loaded mapping %d: zip_name=%s, target_file_path=%s, target_file_dir=%s",
                index,
                zip_name,
                target_file_path,
                target_file_dir,
            )

            mappings.append(
                CertificateMapping(
                    zip_name=zip_name,
                    target_file_path=target_file_path,
                    target_file_dir=target_file_dir,
                )
            )

        source_zip_file_path = _require_str(
            cert_data,
            "source_zip_file_path",
            "certificates",
        )
        temp_dir = _optional_str(cert_data, "temp_dir", "certificates")

        config = AppConfig(
            certificates=CertificatesConfig(
                source_zip_file_path=source_zip_file_path,
                temp_dir=temp_dir,
                mappings=mappings,
            )
        )
        logger.info(
            "Config loaded successfully: source_zip_file_path=%s, mappings=%d",
            source_zip_file_path,
            len(mappings),
        )
        return config

    except FileNotFoundError:
        logger.error("Config file not found: %s", config_path)
        raise FileNotFoundError(f"Config file not found: {config_path}")

    except yaml.YAMLError as e:
        logger.exception("Failed to parse YAML config: %s", config_path)
        raise ValueError(f"YAML parse error: {e}") from e

    except ValueError:
        logger.exception("Invalid config file: %s", config_path)
        raise

    except Exception as e:
        logger.exception("Failed to read config: %s", config_path)
        raise RuntimeError(f"Failed to read config: {e}") from e
