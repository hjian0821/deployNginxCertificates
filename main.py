import argparse
import logging

from config import read_config
from deploy import process_certificates


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy nginx certificate files from configured zip mappings."
    )
    parser.add_argument(
        "-c",
        "--config",
        default="./config.yaml",
        help="Path to the YAML config file. Defaults to ./config.yaml.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level. Defaults to INFO.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    try:
        config = read_config(args.config)
        process_certificates(config)
    except Exception as e:
        logging.error("Program exited: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
