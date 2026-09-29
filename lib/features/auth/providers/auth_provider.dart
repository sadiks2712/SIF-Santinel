import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../shared/models/user_model.dart';
import '../../../core/security/rbac_service.dart';
import '../../../core/security/security_audit_service.dart';
import '../../../core/security/session_security_service.dart';
import '../data/auth_repository.dart';

enum AuthMethod { employeeId, ssoSaml, biometric }

/// Comprehensive Authentication & Startup Session Status
enum AuthStatus {
  initial,            // Startup: Initializing Firebase & verifying session
  unauthenticated,    // No session: Show LoginScreen
  authenticated,      // Valid active user & recognized role: Show Role Dashboard
  accountInactive,    // User authenticated, but isActive == false in Firestore
  accountPending,     // User authenticated, but role == null or unassigned in Firestore
  profileNotFound,    // User authenticated in Firebase, but users/{uid} missing in Firestore
  configError,        // User authenticated, but role in Firestore is unknown
  initError,          // Firebase initialization failed: Show Retry screen
}

class AuthState {
  final AuthStatus status;
  final UserModel? currentUser;
  final String? employeeId;
  final String? pendingUid;
  final bool isLoading;
  final String? errorMessage;
  final String? errorCode;
  final bool isBiometricEnabled;
  final String sessionToken;
  final AuthMethod lastAuthMethod;
  final bool isSessionLocked;
  final bool isSessionExpired;

  const AuthState({
    this.status = AuthStatus.initial,
    this.currentUser,
    this.employeeId,
    this.pendingUid,
    this.isLoading = false,
    this.errorMessage,
    this.errorCode,
    this.isBiometricEnabled = true,
    this.sessionToken = '',
    this.lastAuthMethod = AuthMethod.employeeId,
    this.isSessionLocked = false,
    this.isSessionExpired = false,
  });

  bool get isAuthenticated => status == AuthStatus.authenticated && currentUser != null;

  UserModel get user => currentUser ?? UserModel.defaultSafetyOfficer;

  AuthState copyWith({
    AuthStatus? status,
    UserModel? currentUser,
    String? employeeId,
    String? pendingUid,
    bool? isLoading,
    String? errorMessage,
    String? errorCode,
    bool? isBiometricEnabled,
    String? sessionToken,
    AuthMethod? lastAuthMethod,
    bool? isSessionLocked,
    bool? isSessionExpired,
    bool clearError = false,
    bool clearUser = false,
  }) {
    return AuthState(
      status: status ?? this.status,
      currentUser: clearUser ? null : (currentUser ?? this.currentUser),
      employeeId: employeeId ?? this.employeeId,
      pendingUid: pendingUid ?? this.pendingUid,
      isLoading: isLoading ?? this.isLoading,
      errorMessage: clearError ? null : (errorMessage ?? this.errorMessage),
      errorCode: clearError ? null : (errorCode ?? this.errorCode),
      isBiometricEnabled: isBiometricEnabled ?? this.isBiometricEnabled,
      sessionToken: sessionToken ?? this.sessionToken,
      lastAuthMethod: lastAuthMethod ?? this.lastAuthMethod,
      isSessionLocked: isSessionLocked ?? this.isSessionLocked,
      isSessionExpired: isSessionExpired ?? this.isSessionExpired,
    );
  }
}

class AuthNotifier extends StateNotifier<AuthState> {
  final AuthRepository _repository = AuthRepository();
  final SecurityAuditService _auditService = SecurityAuditService();
  final SessionSecurityService _sessionService = SessionSecurityService();

  AuthNotifier() : super(const AuthState(status: AuthStatus.initial)) {
    _initSession();
    initializeAndCheckSession();
  }

  void _initSession() {
    _sessionService.initialize(
      onSessionExpired: () {
        if (state.isAuthenticated) {
          state = state.copyWith(
            isSessionLocked: true,
            isSessionExpired: true,
            errorMessage: 'Your session has expired due to 15-minute inactivity watchdog.',
            errorCode: 'SESSION_EXPIRED',
          );
          if (state.currentUser != null) {
            _auditService.logEvent(
              type: AuditEventType.sessionTimeout,
              employeeId: state.currentUser!.employeeId,
              actorName: state.currentUser!.name,
              role: state.currentUser!.userRole,
              actionDescription: 'Session locked due to 15-minute inactivity watchdog timeout',
              outcome: 'WARNING',
            );
          }
        }
      },
    );
  }

  /// Exact Startup Flow: Initialize Firebase -> Check Auth Session -> Fetch Firestore Profile -> Route
  Future<void> initializeAndCheckSession() async {
    state = state.copyWith(status: AuthStatus.initial, isLoading: true, clearError: true);

    try {
      final user = await _repository.checkFirebaseSessionAndProfile();
      if (!mounted) return;

      if (user == null) {
        state = state.copyWith(
          status: AuthStatus.unauthenticated,
          isLoading: false,
          clearUser: true,
        );
      } else {
        state = state.copyWith(
          status: AuthStatus.authenticated,
          currentUser: user,
          employeeId: user.employeeId,
          isLoading: false,
          isSessionLocked: false,
          isSessionExpired: false,
        );
        _sessionService.unlockSession();
      }
    } on ProfileNotFoundException catch (e) {
      if (!mounted) return;
      state = state.copyWith(
        status: AuthStatus.profileNotFound,
        pendingUid: e.uid,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'PROFILE_NOT_FOUND',
      );
    } on AccountPendingException catch (e) {
      if (!mounted) return;
      state = state.copyWith(
        status: AuthStatus.accountPending,
        employeeId: e.employeeId,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'ACCOUNT_PENDING',
      );
    } on AccountDisabledException catch (e) {
      if (!mounted) return;
      state = state.copyWith(
        status: AuthStatus.accountInactive,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'USER_DISABLED',
      );
    } on RoleUnassignedException catch (e) {
      if (!mounted) return;
      state = state.copyWith(
        status: AuthStatus.accountPending,
        employeeId: e.employeeId,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'ROLE_UNASSIGNED',
      );
    } on UnknownRoleException catch (e) {
      if (!mounted) return;
      state = state.copyWith(
        status: AuthStatus.configError,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'UNKNOWN_ROLE',
      );
    } on FirebaseInitException catch (e) {
      if (!mounted) return;
      state = state.copyWith(
        status: AuthStatus.initError,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'FIREBASE_INIT_ERROR',
      );
    } catch (e) {
      if (!mounted) return;
      debugPrint('Session check error: $e');
      state = state.copyWith(
        status: AuthStatus.unauthenticated,
        isLoading: false,
        clearUser: true,
      );
    }
  }

  /// Re-check Firestore profile on demand (used by Account Pending / Profile Not Found Retry)
  Future<void> refreshProfile() async {
    await initializeAndCheckSession();
  }

  void clearError() {
    state = state.copyWith(clearError: true);
  }

  /// Primary Sign In with Email / Employee ID and Password
  Future<bool> login(String identifier, String password, {bool rememberMe = true}) async {
    state = state.copyWith(isLoading: true, clearError: true, isSessionExpired: false);

    try {
      final user = await _repository.signIn(
        identifier: identifier,
        password: password,
      );
      if (!mounted) return false;

      state = state.copyWith(
        status: AuthStatus.authenticated,
        currentUser: user,
        employeeId: user.employeeId,
        isLoading: false,
        isSessionLocked: false,
        isSessionExpired: false,
        lastAuthMethod: AuthMethod.employeeId,
        clearError: true,
      );

      _sessionService.unlockSession();
      return true;
    } on ProfileNotFoundException catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        status: AuthStatus.profileNotFound,
        pendingUid: e.uid,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'PROFILE_NOT_FOUND',
      );
      return false;
    } on RoleUnassignedException catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        status: AuthStatus.accountPending,
        employeeId: e.employeeId,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'ROLE_UNASSIGNED',
      );
      return false;
    } on AccountPendingException catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        status: AuthStatus.accountPending,
        employeeId: e.employeeId,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'ACCOUNT_PENDING',
      );
      return false;
    } on AccountDisabledException catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        status: AuthStatus.accountInactive,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'USER_DISABLED',
      );
      return false;
    } on UnknownRoleException catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        status: AuthStatus.configError,
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'UNKNOWN_ROLE',
      );
      return false;
    } on NetworkAuthException catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'NETWORK_ERROR',
      );
      return false;
    } on InvalidCredentialsException catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        isLoading: false,
        errorMessage: e.message,
        errorCode: 'INVALID_CREDENTIALS',
      );
      return false;
    } catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        isLoading: false,
        errorMessage: 'Authentication error. Please try again.',
        errorCode: 'AUTH_ERROR',
      );
      return false;
    }
  }

  /// Enterprise Single Sign-On (SAML 2.0 / OIL Active Directory)
  Future<bool> loginWithSso() async {
    state = state.copyWith(isLoading: true, clearError: true);

    try {
      final user = await _repository.signInWithSso();
      if (!mounted) return false;
      state = state.copyWith(
        status: AuthStatus.authenticated,
        currentUser: user,
        employeeId: user.employeeId,
        isLoading: false,
        isSessionLocked: false,
        isSessionExpired: false,
        lastAuthMethod: AuthMethod.ssoSaml,
        clearError: true,
      );
      _sessionService.unlockSession();
      return true;
    } catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        isLoading: false,
        errorMessage: 'SSO Authentication failed: ${e.toString()}',
        errorCode: 'SSO_FAILED',
      );
      return false;
    }
  }

  /// Hardware Biometric Login (Fingerprint / Face ID)
  Future<bool> loginWithBiometrics() async {
    state = state.copyWith(isLoading: true, clearError: true);

    try {
      final user = await _repository.signInWithBiometrics();
      if (!mounted) return false;
      state = state.copyWith(
        status: AuthStatus.authenticated,
        currentUser: user,
        employeeId: user.employeeId,
        isLoading: false,
        isSessionLocked: false,
        isSessionExpired: false,
        lastAuthMethod: AuthMethod.biometric,
        clearError: true,
      );
      _sessionService.unlockSession();
      return true;
    } catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        isLoading: false,
        errorMessage: 'Biometric authorization failed.',
        errorCode: 'BIOMETRIC_FAILED',
      );
      return false;
    }
  }

  /// Send Password Reset Email via Firebase
  Future<bool> sendPasswordReset(String email) async {
    try {
      await _repository.sendPasswordReset(email);
      return true;
    } catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        errorMessage: e.toString(),
        errorCode: 'RESET_FAILED',
      );
      return false;
    }
  }

  /// Submit New Employee Access Request to SIF Sentinel
  Future<bool> requestAccess({
    required String employeeId,
    required String name,
    required String email,
    required String password,
    required String role,
    required String requestedSite,
    String department = 'Operations & Engineering',
  }) async {
    state = state.copyWith(isLoading: true, clearError: true);
    try {
      await _repository.requestAccess(
        employeeId: employeeId,
        name: name,
        email: email,
        password: password,
        role: role,
        requestedSite: requestedSite,
        department: department,
      );
      if (!mounted) return false;
      state = state.copyWith(
        status: AuthStatus.accountPending,
        employeeId: employeeId,
        isLoading: false,
        clearError: true,
      );
      return true;
    } catch (e) {
      if (!mounted) return false;
      state = state.copyWith(
        isLoading: false,
        errorMessage: e.toString(),
        errorCode: 'REQUEST_FAILED',
      );
      return false;
    }
  }

  /// Unlock Inactive Session with Biometrics / PIN
  void unlockSession() {
    state = state.copyWith(isSessionLocked: false, isSessionExpired: false);
    _sessionService.unlockSession();
    if (state.currentUser != null) {
      _auditService.logEvent(
        type: AuditEventType.loginSuccess,
        employeeId: state.currentUser!.employeeId,
        actorName: state.currentUser!.name,
        role: state.currentUser!.userRole,
        actionDescription: 'Session successfully unlocked with biometric verification',
        outcome: 'SUCCESS',
      );
    }
  }

  /// Set User manually (used by Admin User Management or Switch profile)
  void setUser(UserModel user, {AuthMethod method = AuthMethod.employeeId}) {
    if (!user.isActive) {
      state = state.copyWith(
        status: AuthStatus.accountInactive,
        errorMessage: 'Account is deactivated. Access denied.',
        errorCode: 'USER_DISABLED',
      );
      return;
    }

    state = state.copyWith(
      status: AuthStatus.authenticated,
      currentUser: user,
      employeeId: user.employeeId,
      isLoading: false,
      isSessionLocked: false,
      isSessionExpired: false,
      lastAuthMethod: method,
      clearError: true,
    );
    _sessionService.unlockSession();

    _auditService.logEvent(
      type: AuditEventType.loginSuccess,
      employeeId: user.employeeId,
      actorName: user.name,
      role: user.userRole,
      actionDescription: 'Active user context set: ${user.name} (${user.role}), Scope: ${user.siteScopeFormatted}',
      outcome: 'SUCCESS',
      metadata: {'authMethod': method.name, 'assignedSites': user.assignedSites},
    );
  }

  /// Switch Role / User profile for Administrative Testing
  void switchRole(String roleName) {
    final targetRole = UserRole.tryFromString(roleName);
    final user = UserModel.sampleUsers.firstWhere(
      (u) =>
          u.isActive &&
          ((targetRole != null && u.userRole == targetRole) ||
              u.role.toLowerCase() == roleName.toLowerCase() ||
              u.userRole.displayName.toLowerCase().contains(roleName.toLowerCase()) ||
              u.userRole.key.toLowerCase() == roleName.toLowerCase()),
      orElse: () => UserModel.sampleUsers.firstWhere(
        (u) => (targetRole != null && u.userRole == targetRole),
        orElse: () => UserModel.defaultSafetyOfficer,
      ),
    );
    setUser(user);
  }

  /// Secure Logout: Revoke Firebase Auth session, Purge Secure Storage, Reset State to unauthenticated
  Future<void> logout() async {
    final user = state.currentUser;
    await _repository.signOut(user);
    if (!mounted) return;

    state = const AuthState(
      status: AuthStatus.unauthenticated,
      currentUser: null,
      employeeId: null,
      pendingUid: null,
      isSessionLocked: false,
      isSessionExpired: false,
      sessionToken: '',
    );
  }

  @override
  void dispose() {
    _sessionService.disposeWatchdog();
    super.dispose();
  }
}

final authProvider = StateNotifierProvider<AuthNotifier, AuthState>((ref) {
  return AuthNotifier();
});
