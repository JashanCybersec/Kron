/// Auth state management using Riverpod.
///
/// [AuthNotifier] owns the JWT and exposes login/logout actions.
/// All screens read [authStateProvider] — never access tokens directly.
library;

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../services/api_service.dart';

/// The current authentication state.
sealed class AuthState {
  const AuthState();
}

/// Not yet determined (app startup).
class AuthLoading extends AuthState {
  const AuthLoading();
}

/// User is authenticated with a valid JWT.
class AuthAuthenticated extends AuthState {
  const AuthAuthenticated({
    required this.tenantId,
    required this.role,
    required this.expiresAt,
  });

  final String tenantId;
  final String role;
  final String expiresAt;
}

/// User is not authenticated.
class AuthUnauthenticated extends AuthState {
  const AuthUnauthenticated({this.errorMessage});

  final String? errorMessage;
}

/// Riverpod notifier that manages auth state.
class AuthNotifier extends AutoDisposeAsyncNotifier<AuthState> {
  @override
  Future<AuthState> build() async {
    final api = ref.read(apiServiceProvider);
    final hasToken = await api.hasToken();
    return hasToken ? const AuthAuthenticated(tenantId: '', role: '', expiresAt: '') : const AuthUnauthenticated();
  }

  /// Logs in with email/password and optional TOTP code.
  ///
  /// Updates state to [AuthAuthenticated] on success or
  /// [AuthUnauthenticated] with an error message on failure.
  Future<void> login({
    required String email,
    required String password,
    String? totp,
  }) async {
    state = const AsyncValue.loading();
    final api = ref.read(apiServiceProvider);

    state = await AsyncValue.guard(() async {
      final result = await api.login(email: email, password: password, totp: totp);
      return AuthAuthenticated(
        tenantId: result.tenantId,
        role: result.role,
        expiresAt: result.expiresAt,
      );
    });

    if (state.hasError) {
      state = AsyncValue.data(
        AuthUnauthenticated(errorMessage: state.error?.toString()),
      );
    }
  }

  /// Logs out and revokes the server-side token.
  Future<void> logout() async {
    final api = ref.read(apiServiceProvider);
    await api.logout();
    state = const AsyncValue.data(AuthUnauthenticated());
  }
}

/// Provider for the auth notifier.
final authNotifierProvider =
    AsyncNotifierProvider.autoDispose<AuthNotifier, AuthState>(AuthNotifier.new);
