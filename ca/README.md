# Certificate Authority

# Setup
1. Initialize ca using 
```
(ca directory) bash init.sh
```

# Signing
## Server
1. Copy server.csr from (middleware/data directory) to (ca directory)
2. Run 
```
(ca directory) bash signServer.sh
```
3. Copy server.crt from (ca/certs directory) to (middleware/data directory)

## Client
1. Copy client.csr from (IoT/go directory) to (ca directory)
2. Run 
```
(ca directory) bash signClient.sh
```
3. Copy client.crt from (ca/certs directory) to (IoT/go directory)
