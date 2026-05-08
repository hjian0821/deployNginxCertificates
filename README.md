# certificate-deployer

Deploy nginx certificate files from zip packages using a YAML configuration file.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py --config ./config.yaml
```

`certificates.temp_dir` can be set in `config.yaml` to control where temporary
zip extraction directories are created. If omitted, the system temp directory is
used.

The deploy step checks certificate file permissions before restarting nginx.

## Project Layout

```text
certificate-deployer/
├── config/
│   └── reader.py
├── deploy/
│   └── certificate.py
├── models/
│   └── config.py
├── config-example.yaml
├── config.yaml
├── main.py
├── requirements.txt
└── README.md
```
