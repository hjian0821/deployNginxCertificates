from dataclasses import dataclass, field


@dataclass
class CertificateMapping:
    zip_name: str
    target_file_path: str
    target_file_dir: str = ""


@dataclass
class CertificatesConfig:
    source_zip_file_path: str
    temp_dir: str = ""
    mappings: list[CertificateMapping] = field(default_factory=list)


@dataclass
class AppConfig:
    certificates: CertificatesConfig
