# https-syslog-bridge
This is a lightweight, containerized sidecar service designed to translate incoming HTTPS POST requests into raw TCP packets for Syslog ingestion.

It is built on a minimal Alpine Python image and uses the native Python standard library to minimize attack surface and image size.

## **Features**

* **Protocol Translation:** Accepts HTTPS POST bodies and streams them directly to a raw TCP socket.  
* **Persistent Connections:** Maintains a persistent TCP connection to the upstream Syslog server to handle high throughput efficiently.  
* **Security:**  
  * TLS/SSL termination on port 8443\.  
  * Shared Secret authentication via X-Secret-Key header.  
* **Lightweight:** Zero external Python dependencies (pip is not even used).

## **Project Structure**

.  
├── README.md  
└── src  
    ├── Dockerfile  
    └── bridge.py

## **Prerequisites**

* Docker installed on the host machine.  
* OpenSSL (for generating self-signed certs/secrets if you don't have them).

## **Installation & Setup**

### **1\. Prepare Production Secrets**

For production deployment (Debian/Linux), we recommend storing secrets in /opt inside the project folder.

**Create the directory:**

sudo mkdir \-p /opt/https-syslog-bridge/bridgesecrets  
cd /opt/https-syslog-bridge/bridgesecrets

**Generate a Shared Secret:**

\# Generates a 32-character hex string  
sudo sh \-c 'openssl rand \-hex 16 \> api\_key.txt'

**Generate Self-Signed Certs (if needed):**

sudo openssl req \-x509 \-newkey rsa:4096 \-nodes \-out server.crt \-keyout server.key \-days 3650 \-subj "/CN=https-syslog-bridge"

Secure the Directory:  
Lock down permissions so only root (or the owner) can read the private keys.  
sudo chmod 600 /opt/https-syslog-bridge/bridgesecrets/\*

### **2\. Build the Image**

Navigate to the root of the repository (where this README is) and build using the src context:

docker build \-t https-syslog-bridge ./src

### **3\. Run the Container**

Run the container, mounting the absolute path of your secrets directory to the internal /bridgesecrets path.

docker run \-d \--name https-syslog-bridge \--restart always \-p 8443:8443 \-v /opt/https-syslog-bridge/bridgesecrets:/bridgesecrets \-e SYSLOG\_HOST=10.0.0.50 \-e SYSLOG\_PORT=514 syslog-bridge

## **Configuration**

The following environment variables can be set in the docker run command:

| Variable | Default | Description |
| :---- | :---- | :---- |
| SYSLOG\_HOST | localhost | IP or Hostname of the upstream Syslog server (Raw TCP). |
| SYSLOG\_PORT | 514 | TCP Port of the upstream Syslog server. |
| LISTEN\_PORT | 8443 | Port the container listens on for HTTPS. |
| LOG\_LEVEL | ERROR | Logging verbosity (DEBUG, INFO, WARNING, ERROR). |

\# Get your secret (requires sudo if permissions are locked down)  
SECRET=$(sudo cat /opt/https-syslog-bridge/bridgesecrets/api\_key.txt)

\# Send data  
curl \-k \-v \-X POST https://localhost:8443 \-H "X-Secret-Key: $SECRET" \-H "Content-Type: text/plain" \--data "\<134\>1 2023-10-11T22:14:15.003Z mymachine.example.com su \- ID47 \- BOM 'su root' failed for lonvick on /dev/pts/8"  
