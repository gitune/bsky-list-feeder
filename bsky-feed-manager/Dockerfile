FROM python:3-slim

RUN pip install --no-cache-dir atproto && \
    groupadd -g 1000 manager && \
    useradd -u 1000 -g 1000 -m manager

WORKDIR /app
USER manager

CMD ["/bin/bash"]
