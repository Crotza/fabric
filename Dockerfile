# Start from the official Fabric peer image to get all the OS dependencies
FROM hyperledger/fabric-peer:latest

# Overwrite the official peer binary with our custom-built one
COPY build/bin/peer /usr/local/bin/peer