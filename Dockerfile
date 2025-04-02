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
ENV FLASK_APP=flask_iam:create_app
ENV FLASK_RUN_HOST=0.0.0.0

COPY --chown=app:app . .
RUN pip install .

EXPOSE 5000
CMD ["flask", "run"]
