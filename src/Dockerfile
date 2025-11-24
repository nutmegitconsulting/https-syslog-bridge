FROM python:3.11-alpine

# Keep python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy application code
COPY bridge.py .

# Create the directory where the 'bridgesecrets' volume will be mounted
RUN mkdir /bridgesecrets

# Default Environment Variables (Non-sensitive config only)
ENV SYSLOG_HOST=192.168.1.50
ENV SYSLOG_PORT=514
ENV LISTEN_PORT=8443

# EXMOVED: CERT_FILE, KEY_FILE, and SECRET_FILE_PATH 
# (We now rely on the Python script's internal defaults to find these in /bridgesecrets)

# Expose HTTPS port only
EXPOSE 8443

# Run native python script
CMD ["python", "bridge.py"]
