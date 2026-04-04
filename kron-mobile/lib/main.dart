/// KRON Mobile — entry point.
///
/// Initialises Firebase (push notifications), then launches the app
/// wrapped in a [ProviderScope] for Riverpod state management.
library;

import 'package:firebase_core/firebase_core.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Firebase is required for push notifications (P1/P2 alerts).
  // Fails gracefully if google-services.json is absent (dev builds without Firebase).
  try {
    await Firebase.initializeApp();
  } catch (_) {
    // Firebase not configured — push notifications disabled in this build.
    debugPrint('KRON: Firebase not configured; push notifications disabled.');
  }

  runApp(
    const ProviderScope(
      child: KronApp(),
    ),
  );
}
