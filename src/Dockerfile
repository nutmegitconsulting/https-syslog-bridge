FROM python:3.11-alpine

# Keep python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy application code
COPY bridge.py .

# Create the directory where the 'bridgesecrets' volume will be mounted
RUN mkdir /bridgesecrets

# Default Environment Variables
ENV SYSLOG_HOST=192.168.1.50
ENV SYSLOG_PORT=514
ENV LISTEN_PORT=8443

# Update paths to match the new volume name
ENV CERT_FILE=/bridgesecrets/server.crt
ENV KEY_FILE=/bridgesecrets/server.key
ENV SECRET_FILE_PATH=/bridgesecrets/api_key.txt

# Expose HTTPS port only
EXPOSE 8443

# Run native python script
CMD ["python", "bridge.py"]
