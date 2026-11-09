FROM python:latest
ENV OPENAI_API_KEY=abc123secretvalue
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
