FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Phase-62+ modularized API: app.py now imports many sibling modules
# (config.py, helpers.py, db.py, routers/*, etc). Copy the whole API
# context so runtime imports never miss newly extracted modules.
COPY . .

EXPOSE 8088

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8088"]
