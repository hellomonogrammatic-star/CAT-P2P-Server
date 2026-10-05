FROM dart:stable

WORKDIR /app

COPY server/pubspec.yaml ./pubspec.yaml
RUN dart pub get

COPY server/cat_directory_server.dart ./cat_directory_server.dart

# Render sets PORT for public web services. The Dart server reads it at runtime.
ENV PORT=10000
EXPOSE 10000

CMD ["dart", "run", "cat_directory_server.dart", "--host", "0.0.0.0"]
