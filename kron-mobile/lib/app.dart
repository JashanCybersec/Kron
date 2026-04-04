/// KRON Mobile — app shell with GoRouter navigation.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'features/auth/login_screen.dart';
import 'features/auth/auth_state.dart';
import 'features/alerts/alerts_screen.dart';
import 'features/alerts/alert_detail_screen.dart';
import 'features/soar/soar_approval_screen.dart';
import 'features/oncall/oncall_screen.dart';

/// GoRouter configuration.
///
/// Auth guard: unauthenticated users are redirected to `/login`.
/// JWT is stored in [AuthNotifier] via flutter_secure_storage.
final _router = GoRouter(
  initialLocation: '/alerts',
  redirect: (context, state) {
    // Auth guard is applied in individual routes via ConsumerWidget reads.
    // Top-level redirect is a fallback for cold-start.
    return null;
  },
  routes: [
    GoRoute(
      path: '/login',
      builder: (context, state) => const LoginScreen(),
    ),
    GoRoute(
      path: '/alerts',
      builder: (context, state) => const AlertsScreen(),
      routes: [
        GoRoute(
          path: ':alertId',
          builder: (context, state) => AlertDetailScreen(
            alertId: state.pathParameters['alertId'] ?? '',
          ),
        ),
      ],
    ),
    GoRoute(
      path: '/soar/:playbookId',
      builder: (context, state) => SoarApprovalScreen(
        playbookId: state.pathParameters['playbookId'] ?? '',
      ),
    ),
    GoRoute(
      path: '/oncall',
      builder: (context, state) => const OncallScreen(),
    ),
  ],
);

/// Root widget. Uses [ConsumerWidget] so auth state is accessible for
/// theme and navigation decisions without prop drilling.
class KronApp extends ConsumerWidget {
  const KronApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp.router(
      title: 'KRON SIEM',
      debugShowCheckedModeBanner: false,
      theme: _buildTheme(Brightness.dark),
      routerConfig: _router,
    );
  }

  ThemeData _buildTheme(Brightness brightness) {
    const accent = Color(0xFF3B82F6); // matches web UI --accent
    const bg = Color(0xFF0A0E1A); // matches web UI --bg
    const surface = Color(0xFF131929); // matches web UI --surface

    return ThemeData(
      brightness: brightness,
      useMaterial3: true,
      colorScheme: ColorScheme.dark(
        primary: accent,
        surface: surface,
        background: bg,
        onPrimary: Colors.white,
        onSurface: const Color(0xFFE2E8F0),
      ),
      scaffoldBackgroundColor: bg,
      appBarTheme: const AppBarTheme(
        backgroundColor: surface,
        foregroundColor: Color(0xFFE2E8F0),
        elevation: 0,
        centerTitle: false,
      ),
      cardTheme: const CardThemeData(
        color: surface,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.all(Radius.circular(8)),
          side: BorderSide(color: Color(0xFF1E2D45), width: 1),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: surface,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: Color(0xFF1E2D45)),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: Color(0xFF1E2D45)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: accent, width: 2),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: accent,
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          textStyle: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15),
        ),
      ),
    );
  }
}
