# kron-mobile

Flutter mobile application for the KRON SIEM platform.

Provides security analysts with real-time alert monitoring, SOAR approval
workflows, and on-call management from Android and iOS devices.

## Requirements

- Flutter 3.10+
- Dart 3.0+
- Android SDK 33+ / Xcode 15+

## Development

```bash
flutter pub get
flutter pub run build_runner build --delete-conflicting-outputs
flutter run
```

## Architecture

- **State**: Riverpod 2 (`flutter_riverpod`, `riverpod_annotation`)
- **Navigation**: `go_router`
- **API**: All calls go through `lib/services/api_service.dart` via `dio`
- **Auth**: JWT stored in `flutter_secure_storage`; biometric via `local_auth`
- **Push notifications**: Firebase Cloud Messaging

## Configuration

Copy `lib/config/app_config.dart.example` to `lib/config/app_config.dart`
and set `apiBaseUrl` to your kron-query-api endpoint.

## Backend

Connects to `kron-query-api` (REST + WebSocket). See the main KRON repository
for backend setup.
