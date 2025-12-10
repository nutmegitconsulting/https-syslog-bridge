import socket
import os
import logging
import http.server
import ssl
import threading

# --------------------------------------------------------------------------------
# SYSLOG HTTPS -> TCP BRIDGE
# --------------------------------------------------------------------------------
# Security Note:
# This service requires a "Shared Secret" authentication model.
# The sender must include the header 'X-Secret-Key' matching the content
# of the secret file stored in the container.
#
# To generate a robust 32-character secret for the 'api_key.txt' file:
#   openssl rand -hex 16 > api_key.txt
# --------------------------------------------------------------------------------

# Configuration
SYSLOG_HOST = os.getenv('SYSLOG_HOST', 'localhost')
SYSLOG_PORT = int(os.getenv('SYSLOG_PORT', 514))
DISABLE_TLS = os.getenv('DISABLE_TLS', 'false').lower() == 'true'

# Default to port 8443 inside container
LISTEN_PORT = int(os.getenv('LISTEN_PORT', 8443))

# Certificate paths
# Now defaulting to the /bridgesecrets directory
CERT_FILE = os.getenv('CERT_FILE', '/bridgesecrets/server.crt')
KEY_FILE = os.getenv('KEY_FILE', '/bridgesecrets/server.key')

# Auth Secret Configuration
# We expect a text file containing ONLY the secret string
SECRET_FILE_PATH = os.getenv('SECRET_FILE_PATH', '/bridgesecrets/api_key.txt')

LOG_LEVEL = os.getenv('LOG_LEVEL', 'ERROR')

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
            exit(1)
            
        logger.info(f"Authentication secret loaded. Length: {len(API_SECRET)} chars.")
        
    except FileNotFoundError:
        logger.critical(f"Security Error: 'api_key.txt' not found at {SECRET_FILE_PATH}.")
        logger.critical("Please mount the 'bridgesecrets' volume to '/bridgesecrets'.")
        exit(1)
    except Exception as e:
        logger.critical(f"Error reading secret file: {e}")
        exit(1)

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
        # Ensure only one thread writes to the socket at a time
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
    Handles HTTPS requests and forwards body to Syslog TCP.
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

    if not DISABLE_TLS:
        # Only wrap in SSL if TLS is NOT disabled
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            logger.info(f"Starting HTTPS Syslog Bridge on port {LISTEN_PORT}...")
        except FileNotFoundError:
            logger.critical(f"Certificates not found. Cannot start.")
            exit(1)
    else:
        logger.info(f"Starting HTTP (No TLS) Syslog Bridge on port {LISTEN_PORT}...")

    httpd.serve_forever()
    except FileNotFoundError:
        logger.critical(f"Certificates not found at {CERT_FILE} or {KEY_FILE}. Cannot start.")
        exit(1)


