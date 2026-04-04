/// KRON API service — all HTTP calls go through this class.
///
/// Uses Dio for HTTP with automatic JWT injection via an interceptor.
/// All API calls are per CLAUDE.md: no direct fetch/http calls in screens.
library;

import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../models/alert.dart';
import '../features/soar/soar_approval_screen.dart';
import '../features/oncall/oncall_screen.dart';

/// Provider that exposes the singleton [ApiService].
final apiServiceProvider = Provider<ApiService>((ref) {
  return ApiService();
});

/// HTTP client wrapping Dio with KRON-specific configuration.
class ApiService {
  late final Dio _dio;
  final _storage = const FlutterSecureStorage();

  static const _tokenKey = 'kron_jwt';

  ApiService() {
    _dio = Dio(
      BaseOptions(
        // Base URL is configured via compile-time environment variables:
        //   flutter run --dart-define=KRON_API_URL=https://kron.example.com
        baseUrl: const String.fromEnvironment(
          'KRON_API_URL',
          defaultValue: 'http://localhost:3000/api/v1',
        ),
        connectTimeout: const Duration(seconds: 10),
        receiveTimeout: const Duration(seconds: 30),
        headers: {'Content-Type': 'application/json'},
      ),
    );

    // JWT injection interceptor.
    _dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) async {
          final token = await _storage.read(key: _tokenKey);
          if (token != null) {
            options.headers['Authorization'] = 'Bearer $token';
          }
          return handler.next(options);
        },
        onError: (error, handler) {
          // 401 → clear token (session expired or revoked).
          if (error.response?.statusCode == 401) {
            _storage.delete(key: _tokenKey);
          }
          return handler.next(error);
        },
      ),
    );
  }

  // ── Auth ────────────────────────────────────────────────────────────────────

  /// Authenticates with email/password and optional TOTP.
  ///
  /// Stores the returned JWT in secure storage on success.
  ///
  /// Throws [DioException] on network or authentication errors.
  Future<LoginResult> login({
    required String email,
    required String password,
    String? totp,
  }) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/auth/login',
      data: {
        'email': email,
        'password': password,
        if (totp != null) 'totp': totp,
      },
    );

    final data = response.data!;
    final token = data['token'] as String;
    await _storage.write(key: _tokenKey, value: token);

    return LoginResult(
      token: token,
      tenantId: data['tenant_id'] as String,
      role: data['role'] as String,
      expiresAt: data['expires_at'] as String,
    );
  }

  /// Logs out and revokes the current token server-side.
  Future<void> logout() async {
    try {
      await _dio.post<void>('/auth/logout');
    } finally {
      await _storage.delete(key: _tokenKey);
    }
  }

  /// Returns `true` if a JWT is stored (does not validate expiry).
  Future<bool> hasToken() async {
    final token = await _storage.read(key: _tokenKey);
    return token != null && token.isNotEmpty;
  }

  // ── Alerts ──────────────────────────────────────────────────────────────────

  /// Fetches the paginated alert list.
  ///
  /// [severity] — optional filter (e.g. `"p1"`, `"p2"`).
  /// [status]   — optional filter (e.g. `"open"`, `"acknowledged"`).
  /// [limit]    — max results (default 50).
  Future<List<Alert>> listAlerts({
    String? severity,
    String? status,
    int limit = 50,
  }) async {
    final response = await _dio.get<List<dynamic>>(
      '/alerts',
      queryParameters: {
        if (severity != null) 'severity': severity,
        if (status != null) 'status': status,
        'limit': limit,
      },
    );

    return (response.data ?? [])
        .map((e) => Alert.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Fetches a single alert by ID.
  Future<Alert> getAlert(String alertId) async {
    final response = await _dio.get<Map<String, dynamic>>('/alerts/$alertId');
    return Alert.fromJson(response.data!);
  }

  /// Acknowledges an alert.
  Future<void> acknowledgeAlert(String alertId) async {
    await _dio.post<void>('/alerts/$alertId/acknowledge');
  }

  /// Updates alert status (e.g. resolve, false positive).
  Future<void> updateAlertStatus(String alertId, String status) async {
    await _dio.patch<void>(
      '/alerts/$alertId',
      data: {'status': status},
    );
  }

  // ── SOAR ─────────────────────────────────────────────────────────────────────

  /// Fetches a pending playbook approval request.
  Future<PlaybookApproval> getPlaybookApproval(String playbookId) async {
    final response =
        await _dio.get<Map<String, dynamic>>('/soar/approvals/$playbookId');
    return PlaybookApproval.fromJson(response.data!);
  }

  /// Approves a SOAR playbook execution (biometric gate must be passed before
  /// calling this method).
  Future<void> approvePlaybook(String playbookId) async {
    await _dio.post<void>('/soar/approvals/$playbookId/approve');
  }

  /// Rejects a SOAR playbook execution.
  Future<void> rejectPlaybook(String playbookId) async {
    await _dio.post<void>('/soar/approvals/$playbookId/reject');
  }

  // ── On-call ───────────────────────────────────────────────────────────────────

  /// Fetches the on-call rotation and upcoming 7-day schedule.
  Future<OncallSchedule> getOncallSchedule() async {
    final response =
        await _dio.get<Map<String, dynamic>>('/oncall/schedule');
    return OncallSchedule.fromJson(response.data!);
  }
}

/// Result of a successful login.
class LoginResult {
  const LoginResult({
    required this.token,
    required this.tenantId,
    required this.role,
    required this.expiresAt,
  });

  final String token;
  final String tenantId;
  final String role;
  final String expiresAt;
}
