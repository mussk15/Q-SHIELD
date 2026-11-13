# =====================================================================
# Q-SHIELD MULTI-STAGE DOCKERFILE
# Stage 1: Compile Native Post-Quantum Cryptography Library (liboqs C)
# Stage 2: Hardened Runtime Container for Server and Dashboard
# =====================================================================

# --------------------------------------------------
# Stage 1: Build native liboqs C library
# --------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    ninja-build \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# Target liboqs version 0.16.0 to match liboqs-python 0.16.0.2
RUN git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs \
    && mkdir build && cd build \
    && cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
        .. \
    && ninja install

# --------------------------------------------------
# Stage 2: Hardened Runtime Container
# --------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Install runtime system dependencies (libpcap for scapy packet capture, curl for health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libssl3 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled liboqs shared libraries from builder stage
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and configuration
COPY config/ config/
COPY qshield/ qshield/
COPY dashboard/ dashboard/
COPY response/ response/
COPY attacks/ attacks/
COPY benchmarks/ benchmarks/
COPY scripts/ scripts/
COPY docs/ docs/

# Create persistent runtime data directories
RUN mkdir -p /app/data /app/logs /app/keys

# Expose Secure Server TCP port (5001) and Streamlit Dashboard port (8501)
EXPOSE 5001
EXPOSE 8501

# Default command starts the post-quantum secure TCP server
CMD ["python", "-m", "qshield.net.secure_server", "--host", "0.0.0.0", "--port", "5001"]

