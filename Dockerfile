FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Dépendances système minimales (compilation de certains paquets Python)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

EXPOSE 8000

# Génération / application des migrations puis lancement du serveur Django
CMD ["sh", "-c", "python manage.py makemigrations ipfeed && python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]

