# syntax=docker/dockerfile:1
# Build from git root with following command:
# docker build -t fiam:latest .
FROM python:3.12-rc-bullseye

# root installs

RUN addgroup --system app && adduser --system --group app
USER app
WORKDIR /app

# CSI code
ENV TZ="Europe/Brussels"
ENV PATH=/home/app/.local/bin/:$PATH
ENV FLASK_APP=tests:create_app
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_DEBUG=true

COPY --chown=app:app . .
RUN git config --global --add safe.directory /app
RUN pip install .

EXPOSE 5000
CMD ["flask", "run"]
