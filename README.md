# SailfishOS App DB

Flask app for comparing Android apps with SailfishOS equivalents and crowd-sourced compatibility reports.

## Requirements
- Python 3.12+
- Docker (optional, recommended for production)

## Local development
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export FLASK_DEBUG=1
python run.py
```

Open http://localhost:5000

## Docker (production)
Build and run with a persistent data volume:
```bash
docker build -t sailfishos-app .
docker run --rm -p 5000:5000 -v sailfishos-data:/app/data sailfishos-app
```

Bind-mount the local `data` directory instead:
```bash
docker run --rm -p 5000:5000 -v "$(pwd)/data:/app/data" sailfishos-app
```

## Configuration
Environment variables:
- `SECRET_KEY`: Flask secret key (required for production)
- `APP_VERSION`: version string shown in templates
- `HCAPTCHA_SITE_KEY`: hCaptcha site key
- `HCAPTCHA_SECRET_KEY`: hCaptcha secret key
- `FLASK_DEBUG`: set to `1` for development mode when using `run.py`
