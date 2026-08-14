FROM python:3.12-alpine

WORKDIR /srv/f2b-dashboard-central

COPY app ./app
COPY web ./web

RUN addgroup -S f2b && adduser -S -G f2b -h /srv/f2b-dashboard-central f2b \
    && mkdir -p /var/lib/f2b-dashboard \
    && chown -R f2b:f2b /srv/f2b-dashboard-central /var/lib/f2b-dashboard

ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    F2B_DASHBOARD_DB=/var/lib/f2b-dashboard/central.db

USER f2b
EXPOSE 8080

CMD ["python3", "app/central.py"]
