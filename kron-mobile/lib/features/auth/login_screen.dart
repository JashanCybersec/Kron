/// Login screen — email/password with optional TOTP.
///
/// Supports biometric fast-login if the device has a stored credential
/// (future: biometric re-auth after first password login).
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:local_auth/local_auth.dart';

import 'auth_state.dart';

class LoginScreen extends ConsumerStatefulWidget {
  const LoginScreen({super.key});

  @override
  ConsumerState<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends ConsumerState<LoginScreen> {
  final _emailCtrl = TextEditingController();
  final _passwordCtrl = TextEditingController();
  final _totpCtrl = TextEditingController();
  final _formKey = GlobalKey<FormState>();

  bool _showTotp = false;
  bool _obscurePassword = true;
  bool _biometricAvailable = false;

  @override
  void initState() {
    super.initState();
    _checkBiometric();
  }

  Future<void> _checkBiometric() async {
    final auth = LocalAuthentication();
    final available = await auth.canCheckBiometrics;
    if (mounted) {
      setState(() => _biometricAvailable = available);
    }
  }

  @override
  void dispose() {
    _emailCtrl.dispose();
    _passwordCtrl.dispose();
    _totpCtrl.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!(_formKey.currentState?.validate() ?? false)) return;

    await ref.read(authNotifierProvider.notifier).login(
          email: _emailCtrl.text.trim(),
          password: _passwordCtrl.text,
          totp: _showTotp && _totpCtrl.text.isNotEmpty ? _totpCtrl.text.trim() : null,
        );

    final authState = ref.read(authNotifierProvider).value;
    if (!mounted) return;

    switch (authState) {
      case AuthAuthenticated():
        context.go('/alerts');
      case AuthUnauthenticated(errorMessage: final msg):
        // If error mentions TOTP, show TOTP field.
        if (msg?.toLowerCase().contains('totp') ?? false) {
          setState(() => _showTotp = true);
        }
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(msg ?? 'Login failed'),
            backgroundColor: const Color(0xFFC81E1E),
          ),
        );
      default:
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    final authAsync = ref.watch(authNotifierProvider);
    final isLoading = authAsync.isLoading;

    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(32),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 400),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    // Logo / wordmark
                    const Text(
                      'KRON',
                      style: TextStyle(
                        fontSize: 36,
                        fontWeight: FontWeight.w800,
                        color: Color(0xFF3B82F6),
                        letterSpacing: 4,
                      ),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Security Intelligence Platform',
                      style: TextStyle(color: Color(0xFF64748B), fontSize: 13),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 40),

                    // Email field
                    TextFormField(
                      controller: _emailCtrl,
                      keyboardType: TextInputType.emailAddress,
                      autofillHints: const [AutofillHints.email],
                      decoration: const InputDecoration(
                        labelText: 'Email',
                        prefixIcon: Icon(Icons.email_outlined),
                      ),
                      validator: (v) =>
                          v == null || !v.contains('@') ? 'Enter a valid email' : null,
                    ),
                    const SizedBox(height: 16),

                    // Password field
                    TextFormField(
                      controller: _passwordCtrl,
                      obscureText: _obscurePassword,
                      autofillHints: const [AutofillHints.password],
                      decoration: InputDecoration(
                        labelText: 'Password',
                        prefixIcon: const Icon(Icons.lock_outline),
                        suffixIcon: IconButton(
                          icon: Icon(_obscurePassword
                              ? Icons.visibility_outlined
                              : Icons.visibility_off_outlined),
                          onPressed: () =>
                              setState(() => _obscurePassword = !_obscurePassword),
                        ),
                      ),
                      validator: (v) =>
                          v == null || v.isEmpty ? 'Password is required' : null,
                    ),

                    // TOTP field (shown after first failed attempt with MFA required)
                    if (_showTotp) ...[
                      const SizedBox(height: 16),
                      TextFormField(
                        controller: _totpCtrl,
                        keyboardType: TextInputType.number,
                        maxLength: 6,
                        decoration: const InputDecoration(
                          labelText: 'TOTP Code',
                          prefixIcon: Icon(Icons.security_outlined),
                          helperText: 'Enter the 6-digit code from your authenticator app',
                          counterText: '',
                        ),
                      ),
                    ],

                    const SizedBox(height: 28),

                    // Login button
                    ElevatedButton(
                      onPressed: isLoading ? null : _submit,
                      child: isLoading
                          ? const SizedBox(
                              height: 20,
                              width: 20,
                              child: CircularProgressIndicator(
                                  color: Colors.white, strokeWidth: 2),
                            )
                          : const Text('Sign In'),
                    ),

                    // Biometric login
                    if (_biometricAvailable) ...[
                      const SizedBox(height: 16),
                      OutlinedButton.icon(
                        onPressed: isLoading ? null : _biometricLogin,
                        icon: const Icon(Icons.fingerprint),
                        label: const Text('Sign in with Biometrics'),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _biometricLogin() async {
    final auth = LocalAuthentication();
    final authenticated = await auth.authenticate(
      localizedReason: 'Authenticate to access KRON SIEM',
      options: const AuthenticationOptions(biometricOnly: true),
    );
    if (authenticated && mounted) {
      // Biometric confirms identity — re-use stored token if valid.
      final hasToken = await ref.read(apiServiceProvider).hasToken();
      if (hasToken && mounted) {
        context.go('/alerts');
      } else if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('No stored session — please sign in with password.')),
        );
      }
    }
  }
}
