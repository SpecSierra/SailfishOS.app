# syntax=docker/dockerfile:1
FROM python:3.12-alpine
WORKDIR /code
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Port configuration (default 4000, use 3000 for dev)
ARG PORT=4000
ENV PORT=${PORT}

# Install necessary build tools and dependencies
RUN apk add --no-cache gcc musl-dev linux-headers

# Copy and install Python dependencies
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

# Copy application code and other files
COPY . .

# Create necessary directories
RUN mkdir -p /code/data/icons

# Command to run the application
CMD gunicorn -b 0.0.0.0:${PORT} "app:create_app()"
