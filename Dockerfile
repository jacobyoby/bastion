# Install bookworm debian image
FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-full \
    python3-pip \
    python3-venv \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -ms /bin/bash paranoid-user

# Copy necessary files
COPY --chown=paranoid-user ./ /home/paranoid-user/

USER paranoid-user
WORKDIR /home/paranoid-user

# gmpy2, fpylll, and protobuf come from pip. The venv compiles the C++ extension.
RUN python3 -m venv /home/paranoid-user/venv
ENV PATH="/home/paranoid-user/venv/bin:${PATH}"
RUN pip install .
