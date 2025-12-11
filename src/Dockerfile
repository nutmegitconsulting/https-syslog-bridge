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
ENV LISTEN_PORT=8080

# Expose HTTP port
EXPOSE 8080

# Run native python script
CMD ["python", "bridge.py"]
