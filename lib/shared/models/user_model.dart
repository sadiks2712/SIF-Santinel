import 'package:cloud_firestore/cloud_firestore.dart';
import '../../core/security/rbac_service.dart';

/// Enterprise User Profile Model for SIF Sentinel (OIL)
class UserModel {
  final String id; // Firebase Auth UID
  final String employeeId; // e.g. OIL-EMP-2491 or OIL00123
  final String name; // Full Name
  final String email; // Corporate Email
  final String role; // 'engineer', 'site_supervisor', 'hse_officer', 'hse_director', 'administrator'
  final List<String> assignedSites; // e.g. ['Duliajan', 'Digboi', 'Moran']
  final String department;
  final bool isActive;
  final String avatarUrl;
  final DateTime? createdAt;
  final DateTime? lastLogin;

  const UserModel({
    required this.id,
    required this.employeeId,
    required this.name,
    required this.email,
    required this.role,
    required this.assignedSites,
    required this.department,
    this.isActive = true,
    this.avatarUrl = '',
    this.createdAt,
    this.lastLogin,
  });

  /// Map string role to typed UserRole enum
  UserRole get userRole => UserRole.fromString(role);

  /// Primary site for display purposes
  String get assignedSite => assignedSites.isNotEmpty ? assignedSites.first : 'Corporate HQ Duliajan';

  /// Formatted site scope string (e.g. "Duliajan • Digboi")
  String get siteScopeFormatted {
    if (assignedSites.isEmpty) return 'Global Corporate HQ';
    if (assignedSites.contains('All Sites') || assignedSites.contains('*') || userRole == UserRole.hseDirectorate || userRole == UserRole.administrator) {
      return 'All Corporate & Operational Sites (Enterprise Scope)';
    }
    return assignedSites.join(' • ');
  }

  /// Check RBAC permission for this user
  bool hasPermission(Permission permission) {
    if (!isActive) return false;
    return RbacService.hasPermission(userRole, permission);
  }

  /// Check if this user is authorized for a specific site
  bool isSiteAuthorized(String siteName) {
    if (!isActive) return false;
    if (userRole == UserRole.hseDirectorate || userRole == UserRole.administrator) return true;
    if (assignedSites.contains('All Sites') || assignedSites.contains('*')) return true;
    return assignedSites.any((s) => s.toLowerCase().trim() == siteName.toLowerCase().trim() ||
        siteName.toLowerCase().contains(s.toLowerCase().trim()) ||
        s.toLowerCase().contains(siteName.toLowerCase().trim()));
  }

  /// Convert to Firestore Map
  Map<String, dynamic> toMap() {
    return {
      'uid': id,
      'employeeId': employeeId,
      'name': name,
      'email': email,
      'role': role,
      'assignedSites': assignedSites,
      'department': department,
      'isActive': isActive,
      'avatarUrl': avatarUrl,
      'createdAt': createdAt != null ? Timestamp.fromDate(createdAt!) : FieldValue.serverTimestamp(),
      'lastLogin': lastLogin != null ? Timestamp.fromDate(lastLogin!) : FieldValue.serverTimestamp(),
    };
  }

  /// Factory from Map / JSON
  factory UserModel.fromMap(Map<String, dynamic> map, {String? docId}) {
    List<String> sites = [];
    if (map['assignedSites'] != null) {
      if (map['assignedSites'] is List) {
        sites = (map['assignedSites'] as List).map((e) => e.toString()).toList();
      } else if (map['assignedSites'] is String) {
        sites = [map['assignedSites'].toString()];
      }
    } else if (map['assignedSite'] != null) {
      sites = [map['assignedSite'].toString()];
    }

    DateTime? created;
    if (map['createdAt'] is Timestamp) {
      created = (map['createdAt'] as Timestamp).toDate();
    } else if (map['createdAt'] is String) {
      created = DateTime.tryParse(map['createdAt']);
    }

    DateTime? login;
    if (map['lastLogin'] is Timestamp) {
      login = (map['lastLogin'] as Timestamp).toDate();
    } else if (map['lastLogin'] is String) {
      login = DateTime.tryParse(map['lastLogin']);
    }

    final status = map['status']?.toString().toLowerCase();
    final bool isUserActive;
    if (status == 'pending') {
      isUserActive = false;
    } else if (map['isActive'] != null) {
      isUserActive = map['isActive'] == true;
    } else if (map['is_active'] != null) {
      isUserActive = map['is_active'] == true;
    } else {
      isUserActive = true;
    }

    return UserModel(
      id: docId ?? map['uid'] ?? map['id'] ?? '',
      employeeId: map['employeeId'] ?? map['employee_id'] ?? 'OIL-EMP-0000',
      name: map['name'] ?? 'OIL Personnel',
      email: map['email'] ?? '',
      role: map['role'] ?? 'hse_officer',
      assignedSites: sites.isNotEmpty ? sites : ['Duliajan Main Complex'],
      department: map['department'] ?? 'HSE Department',
      isActive: isUserActive,
      avatarUrl: map['avatarUrl'] ?? '',
      createdAt: created,
      lastLogin: login,
    );
  }

  UserModel copyWith({
    String? id,
    String? employeeId,
    String? name,
    String? email,
    String? role,
    List<String>? assignedSites,
    String? department,
    bool? isActive,
    String? avatarUrl,
    DateTime? createdAt,
    DateTime? lastLogin,
  }) {
    return UserModel(
      id: id ?? this.id,
      employeeId: employeeId ?? this.employeeId,
      name: name ?? this.name,
      email: email ?? this.email,
      role: role ?? this.role,
      assignedSites: assignedSites ?? this.assignedSites,
      department: department ?? this.department,
      isActive: isActive ?? this.isActive,
      avatarUrl: avatarUrl ?? this.avatarUrl,
      createdAt: createdAt ?? this.createdAt,
      lastLogin: lastLogin ?? this.lastLogin,
    );
  }

  // Pre-configured Verified Organization Directory for Oil India Limited
  static const UserModel defaultAdministrator = UserModel(
    id: 'USR-OIL-ADMIN',
    employeeId: 'OIL-ADMIN-001',
    name: 'System Administrator',
    email: 'admin@oilindia.in',
    role: 'administrator',
    assignedSites: ['All Sites'],
    department: 'Digital Systems & HSE Administration',
    isActive: true,
  );

  static const UserModel defaultSafetyOfficer = UserModel(
    id: 'USR-OIL-084',
    employeeId: 'OIL-EMP-2491',
    name: 'Pranab Jyoti Baruah',
    email: 'pj_baruah@oilindia.in',
    role: 'hse_officer',
    assignedSites: ['Duliajan Main Complex', 'Digboi Refinery Area'],
    department: 'HSE (Health, Safety & Environment)',
    isActive: true,
  );

  static const UserModel defaultPendingUser = UserModel(
    id: 'USR-REQ-099',
    employeeId: 'OIL-EMP-4421',
    name: 'Vikram Chetia (Pending Review)',
    email: 'v_chetia@oilindia.in',
    role: 'engineer',
    assignedSites: ['Duliajan Main Complex'],
    department: 'Drilling & Well Operations',
    isActive: false,
  );

  static const List<UserModel> sampleUsers = [
    defaultAdministrator,
    defaultSafetyOfficer,
    defaultPendingUser,
    UserModel(
      id: 'USR-OIL-102',
      employeeId: 'OIL-EMP-1823',
      name: 'Biren Gogoi',
      email: 'biren_gogoi@oilindia.in',
      role: 'site_supervisor',
      assignedSites: ['Moran Drilling Unit'],
      department: 'Drilling & Rig Operations',
      isActive: true,
    ),
    UserModel(
      id: 'USR-OIL-055',
      employeeId: 'OIL-EMP-3120',
      name: 'Mukesh Hazarika',
      email: 'm_hazarika@oilindia.in',
      role: 'engineer',
      assignedSites: ['Naharkatiya Gathering Station'],
      department: 'Production & Facilities Engineering',
      isActive: true,
    ),
    UserModel(
      id: 'USR-OIL-015',
      employeeId: 'OIL-EMP-0912',
      name: 'Dr. Ranjit Saikia',
      email: 'r_saikia@oilindia.in',
      role: 'hse_director',
      assignedSites: ['All Sites'],
      department: 'HSE Executive Directorate',
      isActive: true,
    ),
    UserModel(
      id: 'USR-OIL-002',
      employeeId: 'OIL-EMP-0450',
      name: 'Anupam Sharma',
      email: 'anupam_s@oilindia.in',
      role: 'administrator',
      assignedSites: ['All Sites'],
      department: 'Digital & IT Systems',
      isActive: true,
    ),
  ];
}
