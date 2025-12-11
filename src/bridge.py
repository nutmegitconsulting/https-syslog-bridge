import socket
import os
import logging
import http.server
import threading
import sys

# --------------------------------------------------------------------------------
# SYSLOG HTTP -> TCP BRIDGE
# --------------------------------------------------------------------------------

# Configuration
SYSLOG_HOST = os.getenv('SYSLOG_HOST', 'localhost')
SYSLOG_PORT = int(os.getenv('SYSLOG_PORT', 514))
LISTEN_PORT = int(os.getenv('LISTEN_PORT', 8080)) # Default changed to 8080

# Auth Secret Configuration
SECRET_FILE_PATH = os.getenv('SECRET_FILE_PATH', '/bridgesecrets/api_key.txt')

LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variable to hold the loaded secret in memory
API_SECRET = None

def load_secret():
    """
    Loads the authentication secret from the persistent volume at startup.
    """
    global API_SECRET
    try:
        with open(SECRET_FILE_PATH, 'r') as f:
            API_SECRET = f.read().strip()
        
        if not API_SECRET:
            logger.critical(f"Security Error: Secret file at {SECRET_FILE_PATH} is empty.")
            sys.exit(1)
            
        logger.info(f"Authentication secret loaded. Length: {len(API_SECRET)} chars.")
        
    except FileNotFoundError:
        logger.critical(f"Security Error: 'api_key.txt' not found at {SECRET_FILE_PATH}.")
        logger.critical("Please mount the 'bridgesecrets' volume to '/bridgesecrets'.")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Error reading secret file: {e}")
        sys.exit(1)

class SyslogClient:
    """
    Manages a persistent TCP connection to the syslog server.
    Thread-safe implementation using a Lock.
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.lock = threading.Lock()

    def connect(self):
        try:
            if self.sock:
                self.sock.close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect((self.host, self.port))
            logger.info(f"Connected to syslog TCP server at {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to connect to syslog server: {e}")
            self.sock = None

    def send(self, data):
        with self.lock:
            if not self.sock:
                self.connect()
            
            if not self.sock:
                return False

            try:
                self.sock.sendall(data)
                return True
            except (BrokenPipeError, ConnectionResetError, socket.timeout):
                logger.warning("Connection lost. Reconnecting...")
                self.connect()
                try:
                    if self.sock:
                        self.sock.sendall(data)
                        return True
                except Exception as e:
                    logger.error(f"Retry failed: {e}")
            except Exception as e:
                logger.error(f"Unexpected socket error: {e}")
            
            return False

syslog_client = SyslogClient(SYSLOG_HOST, SYSLOG_PORT)

class BridgeHandler(http.server.BaseHTTPRequestHandler):
    """
    Handles HTTP requests and forwards body to Syslog TCP.
    Enforces Authentication via X-Secret-Key header.
    """
    
    def log_message(self, format, *args):
        if LOG_LEVEL == 'DEBUG':
             logger.debug("%s - - [%s] %s\n" % (self.client_address[0],
                                         self.log_date_time_string(),
                                         format%args))

    def do_POST(self):
        try:
            # 1. Authentication Check
            auth_header = self.headers.get('X-Secret-Key')
            
            if not auth_header or auth_header != API_SECRET:
                logger.warning(f"Auth Failed: Invalid or missing key from {self.client_address[0]}")
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Unauthorized")
                return

            # 2. Payload Processing
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"No content")
                return

            post_data = self.rfile.read(content_length)
            
            # 3. Forward to Syslog
            if syslog_client.send(post_data):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Forwarded")
            else:
                self.send_response(503)
                self.end_headers()
                self.wfile.write(b"Upstream Unavailable")
                
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            self.send_response(500)
            self.end_headers()

    def do_GET(self):
        # Simple health check
        if self.path == '/health':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    load_secret()

    server_address = ('0.0.0.0', LISTEN_PORT)
    httpd = http.server.ThreadingHTTPServer(server_address, BridgeHandler)

    logger.info(f"Starting HTTP Syslog Bridge on port {LISTEN_PORT}...")
    httpd.serve_forever()
