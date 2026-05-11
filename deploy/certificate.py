import logging
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from stat import S_IMODE

from models import AppConfig, CertificateMapping


logger = logging.getLogger(__name__)


@dataclass
class PermissionIssue:
    path: Path
    message: str
    mode: int


def process_certificates(config: AppConfig) -> None:
    certificates = config.certificates
    source_path = Path(certificates.source_zip_file_path).expanduser().resolve()
    temp_root = _resolve_temp_root(certificates.temp_dir)

    if not source_path.exists():
        message = f"Source certificate path does not exist: {source_path}"
        logger.error(message)
        raise FileNotFoundError(message)

    if not check_nginx_configuration():
        raise RuntimeError("nginx configuration check failed")

    logger.info(
        "Start processing certificates: source_path=%s, temp_dir=%s, mappings=%d",
        source_path,
        temp_root or "system default",
        len(certificates.mappings),
    )

    target_dirs = []

    with _certificate_source_dir(source_path, temp_root) as source_dir:
        for mapping in certificates.mappings:
            target_dir = process_certificate_mapping(source_dir, mapping, temp_root)
            if target_dir is not None:
                target_dirs.append(target_dir)

    if not check_certificate_permissions(target_dirs):
        raise RuntimeError("Certificate permission check failed")

    if not restart_nginx():
        raise RuntimeError("nginx restart failed")

    logger.info("All configured certificates processed")


def process_certificate_mapping(
    source_dir: Path,
    mapping: CertificateMapping,
    temp_root: Path | None = None,
) -> Path | None:
    zip_path = _find_zip_file(source_dir, mapping.zip_name)
    target_dir = _resolve_target_dir(mapping)

    if zip_path is None:
        logger.warning("Certificate zip not found, skip: %s", mapping.zip_name)
        return None

    logger.info("Processing certificate zip: %s -> %s", zip_path, target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_dir.chmod(0o755)
    _clear_directory(target_dir)

    try:
        with tempfile.TemporaryDirectory(
            prefix="cert-unzip-",
            dir=temp_root,
        ) as temp_dir:
            temp_path = Path(temp_dir)

            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_path)

            moved_count = _move_extracted_files(temp_path, target_dir)
            logger.info("Moved %d file(s) to %s", moved_count, target_dir)

    except zipfile.BadZipFile:
        logger.exception("Invalid zip file, skip: %s", zip_path)
        return None

    return target_dir


def check_certificate_permissions(target_dirs: list[Path]) -> bool:
    logger.info("Checking certificate file permissions")

    issues = []
    checked_files = 0

    for target_dir in _unique_paths(target_dirs):
        issues.extend(_check_directory_permissions(target_dir))

        for target_file in target_dir.rglob("*"):
            if not target_file.is_file():
                continue

            checked_files += 1
            issues.extend(_check_file_permissions(target_file))

    if issues:
        for issue in issues:
            logger.error(
                "Certificate permission issue: path=%s, mode=%s, reason=%s",
                issue.path,
                _format_mode(issue.mode),
                issue.message,
            )
        return False

    logger.info(
        "Certificate permission check passed: dirs=%d, files=%d",
        len(target_dirs),
        checked_files,
    )
    return True


def check_nginx_configuration() -> bool:
    logger.info("Checking nginx configuration")

    try:
        result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    except FileNotFoundError:
        logger.error("nginx command not found")
        return False

    if result.returncode != 0:
        logger.error("nginx config check failed: %s", result.stderr.strip())
        return False

    logger.info("nginx config check passed")
    return True


def restart_nginx() -> bool:
    logger.info("Restarting nginx service")
    restart_result = subprocess.run(
        ["systemctl", "restart", "nginx"],
        capture_output=True,
        text=True,
    )

    if restart_result.returncode == 0:
        logger.info("nginx restarted successfully")
        return True

    logger.error("nginx restart failed: %s", restart_result.stderr.strip())
    return False


def _resolve_target_dir(mapping: CertificateMapping) -> Path:
    if mapping.target_file_dir and mapping.target_file_path:
        return Path(mapping.target_file_dir) / mapping.target_file_path
    if mapping.target_file_dir:
        return Path(mapping.target_file_dir)
    return Path(mapping.target_file_path)


def _move_extracted_files(source_dir: Path, target_dir: Path) -> int:
    moved_count = 0

    for source_file in source_dir.rglob("*"):
        if not source_file.is_file():
            continue

        target_file = target_dir / source_file.name
        if target_file.exists():
            logger.debug("Overwrite existing file: %s", target_file)
            target_file.unlink()

        shutil.move(str(source_file), str(target_file))
        _set_certificate_file_permissions(target_file)
        logger.debug("Moved file: %s -> %s", source_file, target_file)
        moved_count += 1

    return moved_count


def _clear_directory(path: Path) -> None:
    for child in path.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def _check_directory_permissions(path: Path) -> list[PermissionIssue]:
    mode = S_IMODE(path.stat().st_mode)
    issues = []

    if not mode & 0o100:
        issues.append(
            PermissionIssue(path, "owner must be able to access directory", mode)
        )

    if mode & 0o002:
        issues.append(
            PermissionIssue(path, "directory must not be world-writable", mode)
        )

    return issues


def _set_certificate_file_permissions(path: Path) -> None:
    if _is_private_key(path):
        path.chmod(0o600)
    else:
        path.chmod(0o644)


def _check_file_permissions(path: Path) -> list[PermissionIssue]:
    mode = S_IMODE(path.stat().st_mode)
    issues = []

    if not mode & 0o400:
        issues.append(PermissionIssue(path, "owner must be able to read file", mode))

    if mode & 0o022:
        issues.append(
            PermissionIssue(
                path,
                "file must not be writable by group or others",
                mode,
            )
        )

    if mode & 0o111:
        issues.append(
            PermissionIssue(path, "certificate file must not be executable", mode)
        )

    if _is_private_key(path) and mode & 0o007:
        issues.append(
            PermissionIssue(path, "private key must not be accessible by others", mode)
        )

    return issues


def _is_private_key(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".key") or name in {"key.pem", "privkey.pem"}


def _format_mode(mode: int) -> str:
    return f"{mode:04o}"


def _unique_paths(paths: list[Path]) -> list[Path]:
    unique_paths = []
    seen = set()

    for path in paths:
        resolved_path = path.resolve()
        if resolved_path in seen:
            continue
        seen.add(resolved_path)
        unique_paths.append(path)

    return unique_paths


class _certificate_source_dir:
    def __init__(self, source_path: Path, temp_root: Path | None = None):
        self.source_path = source_path
        self.temp_root = temp_root
        self.temp_dir: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> Path:
        if self.source_path.is_dir():
            return self.source_path

        self.temp_dir = tempfile.TemporaryDirectory(
            prefix="cert-source-",
            dir=self.temp_root,
        )
        source_dir = Path(self.temp_dir.name)

        logger.info("Extracting source certificate package: %s", self.source_path)
        with zipfile.ZipFile(self.source_path, "r") as zip_ref:
            zip_ref.extractall(source_dir)

        return source_dir

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.temp_dir is not None:
            self.temp_dir.cleanup()


def _find_zip_file(source_dir: Path, zip_name: str) -> Path | None:
    direct_path = source_dir / zip_name
    if direct_path.exists():
        return direct_path

    for zip_path in source_dir.rglob(zip_name):
        if "__MACOSX" in zip_path.parts:
            continue
        if zip_path.is_file():
            return zip_path

    return None


def _resolve_temp_root(temp_dir: str) -> Path | None:
    if not temp_dir:
        return None

    temp_root = Path(temp_dir).expanduser().resolve()
    temp_root.mkdir(parents=True, exist_ok=True)
    return temp_root
