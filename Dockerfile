FROM dart:stable

WORKDIR /app

COPY server/pubspec.yaml server/pubspec.lock* ./
RUN dart pub get

COPY server/ ./

EXPOSE 10000

CMD ["dart", "run", "cat_directory_server.dart"]
