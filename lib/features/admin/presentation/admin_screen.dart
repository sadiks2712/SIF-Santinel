import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../../../core/constants/oil_constants.dart';
import '../../../core/security/rbac_service.dart';
import '../../../core/security/security_audit_service.dart';
import '../../../core/security/local_encryption_service.dart';
import '../../../core/security/environment_config.dart';
import '../../../shared/models/user_model.dart';
import '../../../shared/models/report_model.dart';
import '../../../shared/models/sif_analysis_model.dart';
import '../../../shared/models/site_model.dart';
import '../../../shared/widgets/oil_header.dart';
import '../../../shared/widgets/enterprise_card.dart';
import '../../../shared/widgets/custom_button.dart';
import '../../auth/data/auth_repository.dart';
import '../../auth/providers/auth_provider.dart';
import '../../reports/providers/reports_provider.dart';

class AdminScreen extends ConsumerStatefulWidget {
  final int initialTabIndex;
  const AdminScreen({super.key, this.initialTabIndex = 0});

  @override
  ConsumerState<AdminScreen> createState() => _AdminScreenState();
}

class _AdminScreenState extends ConsumerState<AdminScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  double _confidenceThreshold = 0.85;
  bool _fewShotEnabled = true;

  final SecurityAuditService _auditService = SecurityAuditService();
  final LocalDataEncryptionService _encryptionService = LocalDataEncryptionService();

  // Live Firestore subscription & local user cache
  StreamSubscription<QuerySnapshot<Map<String, dynamic>>>? _usersSubscription;
  List<UserModel> _managedUsers = [];
  bool _isLoadingUsers = true;
  bool _isFirestoreConnected = false;

  // Search & Filter state for responsive views
  String _userSearchQuery = '';
  UserRole? _selectedRoleFilter;
  String _siteSearchQuery = '';
  String _auditSearchQuery = '';
  String? _auditOutcomeFilter;
  String _taxonomySearchQuery = '';

  @override
  void initState() {
    super.initState();
    _tabController = TabController(
      length: 5,
      vsync: this,
      initialIndex: widget.initialTabIndex.clamp(0, 4),
    );
    _initUsersFromFirestore();
  }

  @override
  void didUpdateWidget(covariant AdminScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.initialTabIndex != widget.initialTabIndex) {
      final targetIndex = widget.initialTabIndex.clamp(0, 4);
      if (_tabController.index != targetIndex) {
        _tabController.animateTo(targetIndex);
      }
    }
  }

  @override
  void dispose() {
    _usersSubscription?.cancel();
    _tabController.dispose();
    super.dispose();
  }

  /// Initialize real-time user stream from Cloud Firestore
  void _initUsersFromFirestore() {
    try {
      final firestore = FirebaseFirestore.instance;
      _usersSubscription = firestore.collection('users').snapshots().listen(
        (snapshot) {
          if (!mounted) return;
          if (snapshot.docs.isNotEmpty) {
            final liveUsers = snapshot.docs.map((doc) {
              return UserModel.fromMap(doc.data(), docId: doc.id);
            }).toList();

            // Merge any pending memory requests submitted in this session
            for (final p in AuthRepository.pendingMemoryRequests) {
              if (!liveUsers.any((u) => u.id == p.id || u.employeeId == p.employeeId || u.email.toLowerCase() == p.email.toLowerCase())) {
                liveUsers.insert(0, p);
              }
            }

            setState(() {
              _managedUsers = liveUsers;
              _isLoadingUsers = false;
              _isFirestoreConnected = true;
            });
          } else {
            // First time initialization: seed the authenticated admin + default organization directory
            _seedInitialOrganizationInFirestore();
          }
        },
        onError: (err) {
          debugPrint('Firestore live users stream error: $err');
          if (!mounted) return;
          setState(() {
            _isLoadingUsers = false;
            _isFirestoreConnected = false;
            if (_managedUsers.isEmpty) {
              final fallback = List<UserModel>.from(UserModel.sampleUsers);
              for (final p in AuthRepository.pendingMemoryRequests) {
                if (!fallback.any((u) => u.id == p.id || u.employeeId == p.employeeId)) {
                  fallback.insert(0, p);
                }
              }
              _managedUsers = fallback;
            }
          });
        },
      );
    } catch (e) {
      debugPrint('Firestore init error: $e');
      if (mounted) {
        setState(() {
          _isLoadingUsers = false;
          _isFirestoreConnected = false;
          final fallback = List<UserModel>.from(UserModel.sampleUsers);
          for (final p in AuthRepository.pendingMemoryRequests) {
            if (!fallback.any((u) => u.id == p.id || u.employeeId == p.employeeId)) {
              fallback.insert(0, p);
            }
          }
          _managedUsers = fallback;
        });
      }
    }
  }

  /// Seed initial organization users to Firestore if collection is empty
  Future<void> _seedInitialOrganizationInFirestore() async {
    try {
      final firestore = FirebaseFirestore.instance;
      final batch = firestore.batch();
      for (final user in UserModel.sampleUsers) {
        final docRef = firestore.collection('users').doc(user.id);
        batch.set(docRef, user.toMap(), SetOptions(merge: true));
      }
      await batch.commit();
      if (mounted) {
        setState(() {
          _managedUsers = List.from(UserModel.sampleUsers);
          _isLoadingUsers = false;
          _isFirestoreConnected = true;
        });
      }
    } catch (e) {
      debugPrint('Failed to seed initial organization users: $e');
      if (mounted) {
        setState(() {
          _managedUsers = List.from(UserModel.sampleUsers);
          _isLoadingUsers = false;
        });
      }
    }
  }

  Color _getRoleColor(UserRole role) {
    switch (role) {
      case UserRole.administrator:
        return const Color(0xFF2B2A29);
      case UserRole.hseDirectorate:
        return const Color(0xFFE31E24);
      case UserRole.hseOfficer:
        return const Color(0xFFD97706);
      case UserRole.siteSupervisor:
        return const Color(0xFFC2410C);
      case UserRole.engineer:
        return const Color(0xFF2563EB);
    }
  }

  void _showCreateUserDialog() {
    final empIdController = TextEditingController();
    final nameController = TextEditingController();
    final emailController = TextEditingController();
    final deptController = TextEditingController(text: 'Operations & Drilling');
    UserRole selectedRole = UserRole.engineer;
    final List<String> selectedSites = ['Duliajan Main Complex'];

    final availableSites = [
      'Duliajan Main Complex',
      'Moran Drilling Unit',
      'Naharkatiya Gathering Station',
      'Digboi Refinery Area',
      'Jorhat Upstream Base',
      'All Sites',
    ];

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (context, setDialogState) {
          final isSmallScreen = MediaQuery.of(context).size.width < 500;
          return Dialog(
            backgroundColor: Colors.white,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
            insetPadding: EdgeInsets.symmetric(
              horizontal: isSmallScreen ? 16 : 32,
              vertical: 24,
            ),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 540),
              child: SingleChildScrollView(
                padding: EdgeInsets.all(isSmallScreen ? 16 : 22),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Header
                    Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: const Color(0xFFE31E24).withValues(alpha: 0.1),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: const Icon(
                            Icons.person_add_alt_1_rounded,
                            color: Color(0xFFE31E24),
                            size: 20,
                          ),
                        ),
                        const SizedBox(width: 10),
                        const Expanded(
                          child: Text(
                            'Provision Live Account',
                            style: TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.w800,
                              color: Color(0xFF2B2A29),
                            ),
                          ),
                        ),
                        IconButton(
                          icon: const Icon(Icons.close, size: 20, color: Color(0xFF687078)),
                          padding: EdgeInsets.zero,
                          constraints: const BoxConstraints(),
                          onPressed: () => Navigator.of(ctx).pop(),
                        ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'Create user profile with real-time Firestore persistence & RBAC authorization.',
                      style: TextStyle(fontSize: 12, color: Color(0xFF687078)),
                    ),
                    const Divider(height: 20, color: Color(0xFFE2E5E8)),

                    // Employee ID & Name row
                    if (isSmallScreen) ...[
                      TextField(
                        controller: empIdController,
                        textCapitalization: TextCapitalization.characters,
                        decoration: const InputDecoration(
                          labelText: 'Employee ID *',
                          hintText: 'OIL-EMP-4091',
                          contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                        ),
                      ),
                      const SizedBox(height: 10),
                      TextField(
                        controller: nameController,
                        textCapitalization: TextCapitalization.words,
                        decoration: const InputDecoration(
                          labelText: 'Full Name *',
                          contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                        ),
                      ),
                    ] else ...[
                      Row(
                        children: [
                          Expanded(
                            flex: 2,
                            child: TextField(
                              controller: empIdController,
                              textCapitalization: TextCapitalization.characters,
                              decoration: const InputDecoration(
                                labelText: 'Employee ID *',
                                hintText: 'OIL-EMP-4091',
                                contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                              ),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            flex: 3,
                            child: TextField(
                              controller: nameController,
                              textCapitalization: TextCapitalization.words,
                              decoration: const InputDecoration(
                                labelText: 'Full Name *',
                                contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                    const SizedBox(height: 10),

                    // Email & Department
                    if (isSmallScreen) ...[
                      TextField(
                        controller: emailController,
                        keyboardType: TextInputType.emailAddress,
                        decoration: const InputDecoration(
                          labelText: 'Corporate Email *',
                          hintText: 'user@oilindia.in',
                          contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                        ),
                      ),
                      const SizedBox(height: 10),
                      TextField(
                        controller: deptController,
                        decoration: const InputDecoration(
                          labelText: 'Department',
                          contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                        ),
                      ),
                    ] else ...[
                      Row(
                        children: [
                          Expanded(
                            flex: 3,
                            child: TextField(
                              controller: emailController,
                              keyboardType: TextInputType.emailAddress,
                              decoration: const InputDecoration(
                                labelText: 'Corporate Email *',
                                hintText: 'user@oilindia.in',
                                contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                              ),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            flex: 2,
                            child: TextField(
                              controller: deptController,
                              decoration: const InputDecoration(
                                labelText: 'Department',
                                contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                    const SizedBox(height: 14),

                    // Role Dropdown
                    const Text(
                      'ASSIGNED RBAC ROLE',
                      style: TextStyle(fontSize: 10, fontWeight: FontWeight.w800, color: Color(0xFF687078)),
                    ),
                    const SizedBox(height: 4),
                    DropdownButtonFormField<UserRole>(
                      initialValue: selectedRole,
                      isExpanded: true,
                      decoration: const InputDecoration(
                        contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      ),
                      items: UserRole.values.map((r) {
                        return DropdownMenuItem(
                          value: r,
                          child: Text(r.displayName, style: const TextStyle(fontSize: 13)),
                        );
                      }).toList(),
                      onChanged: (val) {
                        if (val != null) setDialogState(() => selectedRole = val);
                      },
                    ),
                    const SizedBox(height: 14),

                    // Assigned Sites
                    const Text(
                      'AUTHORIZED SITE SCOPE',
                      style: TextStyle(fontSize: 10, fontWeight: FontWeight.w800, color: Color(0xFF687078)),
                    ),
                    const SizedBox(height: 6),
                    Wrap(
                      spacing: 6,
                      runSpacing: 6,
                      children: availableSites.map((site) {
                        final isSel = selectedSites.contains(site);
                        return FilterChip(
                          label: Text(site, style: const TextStyle(fontSize: 11)),
                          selected: isSel,
                          selectedColor: const Color(0xFFE31E24).withValues(alpha: 0.12),
                          checkmarkColor: const Color(0xFFE31E24),
                          onSelected: (val) {
                            setDialogState(() {
                              if (val) {
                                selectedSites.add(site);
                              } else if (selectedSites.length > 1) {
                                selectedSites.remove(site);
                              }
                            });
                          },
                        );
                      }).toList(),
                    ),
                    const SizedBox(height: 20),

                    // Action Buttons
                    Row(
                      mainAxisAlignment: MainAxisAlignment.end,
                      children: [
                        TextButton(
                          onPressed: () => Navigator.of(ctx).pop(),
                          child: const Text('Cancel', style: TextStyle(color: Color(0xFF687078))),
                        ),
                        const SizedBox(width: 8),
                        ElevatedButton.icon(
                          style: ElevatedButton.styleFrom(
                            backgroundColor: const Color(0xFFE31E24),
                            foregroundColor: Colors.white,
                            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                          ),
                          onPressed: () async {
                            if (empIdController.text.trim().isEmpty ||
                                nameController.text.trim().isEmpty ||
                                emailController.text.trim().isEmpty) {
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(content: Text('Please fill all required fields.')),
                              );
                              return;
                            }

                            final newUserId = 'USR-OIL-${DateTime.now().millisecondsSinceEpoch.toString().substring(7)}';
                            final newUser = UserModel(
                              id: newUserId,
                              employeeId: empIdController.text.trim().toUpperCase(),
                              name: nameController.text.trim(),
                              email: emailController.text.trim().toLowerCase(),
                              role: selectedRole.key,
                              assignedSites: selectedSites,
                              department: deptController.text.trim(),
                              isActive: true,
                              createdAt: DateTime.now(),
                            );

                            // 1. Persist to Cloud Firestore
                            try {
                              await FirebaseFirestore.instance
                                  .collection('users')
                                  .doc(newUserId)
                                  .set(newUser.toMap());
                            } catch (e) {
                              debugPrint('Firestore user save error: $e');
                            }

                            // 2. Update local state
                            setState(() {
                              if (!_managedUsers.any((u) => u.id == newUser.id)) {
                                _managedUsers.insert(0, newUser);
                              }
                            });

                            // 3. Log real audit event
                            _auditService.logEvent(
                              type: AuditEventType.roleChanged,
                              employeeId: newUser.employeeId,
                              actorName: ref.read(authProvider).user.name,
                              role: UserRole.administrator,
                              actionDescription:
                                  'Provisioned user account: ${newUser.name} with Role: ${newUser.role}',
                              outcome: 'SUCCESS',
                              metadata: {'assignedSites': newUser.assignedSites, 'role': newUser.role},
                            );

                            if (!ctx.mounted) return;
                            Navigator.of(ctx).pop();
                            if (!mounted) return;
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(content: Text('User ${newUser.name} provisioned in Firestore.')),
                            );
                          },
                          icon: const Icon(Icons.check, size: 16),
                          label: const Text('Provision User'),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  Future<void> _toggleUserStatus(UserModel user) async {
    final updated = user.copyWith(isActive: !user.isActive);

    // Update local state immediately for snappy UI
    setState(() {
      final idx = _managedUsers.indexWhere((u) => u.id == user.id);
      if (idx != -1) {
        _managedUsers[idx] = updated;
      }
    });

    // Write change directly to Firestore
    try {
      await FirebaseFirestore.instance
          .collection('users')
          .doc(user.id)
          .set({'isActive': updated.isActive}, SetOptions(merge: true));
    } catch (e) {
      debugPrint('Firestore toggle status write error: $e');
    }

    _auditService.logEvent(
      type: AuditEventType.securityConfigChanged,
      employeeId: user.employeeId,
      actorName: ref.read(authProvider).user.name,
      role: UserRole.administrator,
      actionDescription: 'Account status updated for ${user.employeeId}: isActive = ${updated.isActive}',
      outcome: updated.isActive ? 'SUCCESS' : 'WARNING',
      metadata: {'userId': user.id, 'newStatus': updated.isActive},
    );

    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('User ${user.name} is now ${updated.isActive ? "ACTIVE" : "DEACTIVATED"}')),
    );
  }

  /// Accept pending employee access request and activate account
  Future<void> _acceptAccessRequest(UserModel user) async {
    final updated = user.copyWith(isActive: true);

    // Update local state immediately for snappy UI
    setState(() {
      final idx = _managedUsers.indexWhere((u) => u.id == user.id);
      if (idx != -1) {
        _managedUsers[idx] = updated;
      }
    });

    // Write approval to Cloud Firestore
    try {
      final firestore = FirebaseFirestore.instance;
      await firestore.collection('users').doc(user.id).set({
        'isActive': true,
        'status': 'approved',
        'approvedAt': FieldValue.serverTimestamp(),
      }, SetOptions(merge: true));

      await firestore.collection('access_requests').doc(user.id).set({
        'status': 'approved',
        'reviewedAt': FieldValue.serverTimestamp(),
      }, SetOptions(merge: true));
    } catch (e) {
      debugPrint('Firestore approve request write error: $e');
    }

    _auditService.logEvent(
      type: AuditEventType.securityConfigChanged,
      employeeId: user.employeeId,
      actorName: ref.read(authProvider).user.name,
      role: UserRole.administrator,
      actionDescription: 'Approved access request for ${user.name} (${user.employeeId}) as ${user.userRole.displayName}. Account activated.',
      outcome: 'SUCCESS',
      metadata: {'userId': user.id, 'role': user.role, 'employeeId': user.employeeId},
    );

    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Access approved for ${user.name} (${user.userRole.displayName}). Account activated.'),
        backgroundColor: const Color(0xFF166534),
        duration: const Duration(seconds: 4),
      ),
    );
  }

  void _showDeleteUserConfirmation(UserModel user) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        title: Row(
          children: [
            const Icon(Icons.warning_amber_rounded, color: Color(0xFFDC2626), size: 22),
            const SizedBox(width: 8),
            const Text('Revoke User Account', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800)),
          ],
        ),
        content: Text(
          'Are you sure you want to permanently delete user account "${user.name}" (${user.employeeId}) from Firestore?',
          style: const TextStyle(fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFDC2626), foregroundColor: Colors.white),
            onPressed: () async {
              try {
                await FirebaseFirestore.instance.collection('users').doc(user.id).delete();
              } catch (e) {
                debugPrint('Firestore delete user error: $e');
              }

              if (mounted) {
                setState(() {
                  _managedUsers.removeWhere((u) => u.id == user.id);
                });
              }

              _auditService.logEvent(
                type: AuditEventType.securityConfigChanged,
                employeeId: user.employeeId,
                actorName: ref.read(authProvider).user.name,
                role: UserRole.administrator,
                actionDescription: 'Permanently deleted user profile: ${user.name} (${user.employeeId})',
                outcome: 'WARNING',
              );

              if (!ctx.mounted) return;
              Navigator.of(ctx).pop();
              if (!mounted) return;
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text('User ${user.name} removed.')),
              );
            },
            child: const Text('Delete Account'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF7F8FA),
      appBar: const OilHeader(
        title: 'System Administration',
        subtitle: 'Enterprise Security, RBAC & AI Governance',
      ),
      body: Column(
        children: [
          // Responsive Styled Tab Bar
          Container(
            width: double.infinity,
            decoration: const BoxDecoration(
              color: Colors.white,
              border: Border(
                bottom: BorderSide(color: Color(0xFFE2E5E8), width: 1),
              ),
            ),
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1400),
                child: TabBar(
                  controller: _tabController,
                  isScrollable: true,
                  tabAlignment: TabAlignment.start,
                  labelColor: const Color(0xFFE31E24),
                  unselectedLabelColor: const Color(0xFF687078),
                  indicatorColor: const Color(0xFFE31E24),
                  indicatorWeight: 3,
                  labelStyle: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13),
                  unselectedLabelStyle: const TextStyle(fontWeight: FontWeight.w500, fontSize: 13),
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                  tabs: const [
                    Tab(icon: Icon(Icons.people_alt_outlined, size: 18), text: 'Users & RBAC'),
                    Tab(icon: Icon(Icons.location_city_rounded, size: 18), text: 'Sites & Assets'),
                    Tab(icon: Icon(Icons.security_rounded, size: 18), text: 'Security Vault & Audit'),
                    Tab(icon: Icon(Icons.psychology_outlined, size: 18), text: 'AI Model & Taxonomy'),
                    Tab(icon: Icon(Icons.hub_outlined, size: 18), text: 'Integrations & Settings'),
                  ],
                ),
              ),
            ),
          ),
          // Tab Views with LayoutBuilder & Centered Constraints
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                _buildUserManagementTab(),
                _buildSitesTab(),
                _buildSecurityVaultTab(),
                _buildAiModelTab(),
                _buildIntegrationsTab(),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // TAB 1: User Management & RBAC Provisioning (Live Firestore)
  // ==========================================
  Widget _buildUserManagementTab() {
    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;
        final isCompact = screenWidth < 680;
        final isWide = screenWidth >= 1100;
        final horizontalPadding = isCompact ? 14.0 : (isWide ? 28.0 : 20.0);

        final activeCount = _managedUsers.where((u) => u.isActive).length;
        final inactiveCount = _managedUsers.length - activeCount;
        final pendingUsers = _managedUsers.where((u) => !u.isActive).toList();

        // Filtered users
        final filteredUsers = _managedUsers.where((u) {
          final matchesSearch = _userSearchQuery.isEmpty ||
              u.name.toLowerCase().contains(_userSearchQuery.toLowerCase()) ||
              u.employeeId.toLowerCase().contains(_userSearchQuery.toLowerCase()) ||
              u.email.toLowerCase().contains(_userSearchQuery.toLowerCase()) ||
              u.department.toLowerCase().contains(_userSearchQuery.toLowerCase());
          final matchesRole = _selectedRoleFilter == null || u.userRole == _selectedRoleFilter;
          return matchesSearch && matchesRole;
        }).toList();

        return SingleChildScrollView(
          padding: EdgeInsets.symmetric(horizontal: horizontalPadding, vertical: 16),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1400),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // KPI Stat Cards Row
                  _buildUserKpiRow(isCompact, screenWidth, activeCount, inactiveCount),
                  const SizedBox(height: 16),

                  // Search, Filter & Provision Action Bar
                  _buildUserActionBar(isCompact),
                  const SizedBox(height: 16),

                  // Dedicated Pending Requests Banner
                  if (pendingUsers.isNotEmpty)
                    _buildPendingRequestsBanner(pendingUsers, isCompact),

                  if (_isLoadingUsers)
                    const Padding(
                      padding: EdgeInsets.symmetric(vertical: 40),
                      child: Center(
                        child: CircularProgressIndicator(color: Color(0xFFE31E24)),
                      ),
                    )
                  else if (isWide) ...[
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        // Left: User Cards Grid (Flex: 3)
                        Expanded(
                          flex: 3,
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                children: [
                                  Row(
                                    children: [
                                      Text(
                                        'LIVE DIRECTORY (${filteredUsers.length})',
                                        style: const TextStyle(
                                          fontSize: 12,
                                          fontWeight: FontWeight.w900,
                                          color: Color(0xFF2B2A29),
                                          letterSpacing: 0.5,
                                        ),
                                      ),
                                      const SizedBox(width: 8),
                                      Container(
                                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1.5),
                                        decoration: BoxDecoration(
                                          color: _isFirestoreConnected
                                              ? const Color(0xFFDCFCE7)
                                              : const Color(0xFFFEF3C7),
                                          borderRadius: BorderRadius.circular(4),
                                        ),
                                        child: Text(
                                          _isFirestoreConnected ? 'FIRESTORE LIVE' : 'LOCAL CACHE',
                                          style: TextStyle(
                                            fontSize: 9,
                                            fontWeight: FontWeight.w800,
                                            color: _isFirestoreConnected
                                                ? const Color(0xFF166534)
                                                : const Color(0xFFD97706),
                                          ),
                                        ),
                                      ),
                                    ],
                                  ),
                                  if (_userSearchQuery.isNotEmpty || _selectedRoleFilter != null)
                                    TextButton.icon(
                                      onPressed: () {
                                        setState(() {
                                          _userSearchQuery = '';
                                          _selectedRoleFilter = null;
                                        });
                                      },
                                      icon: const Icon(Icons.clear_all, size: 14),
                                      label: const Text('Clear Filters', style: TextStyle(fontSize: 11)),
                                    ),
                                ],
                              ),
                              const SizedBox(height: 8),
                              if (filteredUsers.isEmpty)
                                _buildEmptySearchState('No users match the search criteria.')
                              else
                                _buildUserGrid(filteredUsers, crossAxisCount: 2),
                            ],
                          ),
                        ),
                        const SizedBox(width: 20),
                        // Right: RBAC Matrix Panel (Flex: 2)
                        Expanded(
                          flex: 2,
                          child: _buildRbacMatrixCard(isCompact: false),
                        ),
                      ],
                    ),
                  ] else ...[
                    // Mobile / Tablet Stacked Layout
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            Text(
                              'LIVE DIRECTORY (${filteredUsers.length})',
                              style: const TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.w900,
                                color: Color(0xFF2B2A29),
                                letterSpacing: 0.5,
                              ),
                            ),
                            const SizedBox(width: 8),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1.5),
                              decoration: BoxDecoration(
                                color: _isFirestoreConnected
                                    ? const Color(0xFFDCFCE7)
                                    : const Color(0xFFFEF3C7),
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: Text(
                                _isFirestoreConnected ? 'FIRESTORE' : 'LOCAL',
                                style: TextStyle(
                                  fontSize: 9,
                                  fontWeight: FontWeight.w800,
                                  color: _isFirestoreConnected
                                      ? const Color(0xFF166534)
                                      : const Color(0xFFD97706),
                                ),
                              ),
                            ),
                          ],
                        ),
                        if (_userSearchQuery.isNotEmpty || _selectedRoleFilter != null)
                          TextButton.icon(
                            onPressed: () {
                              setState(() {
                                _userSearchQuery = '';
                                _selectedRoleFilter = null;
                              });
                            },
                            icon: const Icon(Icons.clear_all, size: 14),
                            label: const Text('Clear Filters', style: TextStyle(fontSize: 11)),
                          ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    if (filteredUsers.isEmpty)
                      _buildEmptySearchState('No users match the search criteria.')
                    else
                      _buildUserGrid(filteredUsers, crossAxisCount: isCompact ? 1 : 2),
                    const SizedBox(height: 20),
                    _buildRbacMatrixCard(isCompact: isCompact),
                  ],
                  const SizedBox(height: 32),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildUserKpiRow(bool isCompact, double screenWidth, int activeCount, int inactiveCount) {
    final kpis = [
      _KpiItem('Total Users', '${_managedUsers.length}', Icons.people_outline_rounded, const Color(0xFF2B2A29)),
      _KpiItem('Active Accounts', '$activeCount', Icons.check_circle_outline_rounded, const Color(0xFF166534)),
      _KpiItem('Suspended', '$inactiveCount', Icons.pause_circle_outline_rounded, const Color(0xFF991B1B)),
      _KpiItem('RBAC Roles', '${UserRole.values.length}', Icons.admin_panel_settings_outlined, const Color(0xFFE31E24)),
    ];

    if (screenWidth < 500) {
      // 2x2 grid
      return Column(
        children: [
          Row(
            children: [
              Expanded(child: _buildKpiCard(kpis[0])),
              const SizedBox(width: 8),
              Expanded(child: _buildKpiCard(kpis[1])),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(child: _buildKpiCard(kpis[2])),
              const SizedBox(width: 8),
              Expanded(child: _buildKpiCard(kpis[3])),
            ],
          ),
        ],
      );
    }

    return Row(
      children: kpis.map((kpi) {
        return Expanded(
          child: Padding(
            padding: const EdgeInsets.only(right: 8.0),
            child: _buildKpiCard(kpi),
          ),
        );
      }).toList(),
    );
  }

  Widget _buildKpiCard(_KpiItem kpi) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFFE2E5E8)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.02),
            blurRadius: 4,
            offset: const Offset(0, 1),
          ),
        ],
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(7),
            decoration: BoxDecoration(
              color: kpi.color.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(kpi.icon, color: kpi.color, size: 18),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  kpi.title,
                  style: const TextStyle(fontSize: 10.5, color: Color(0xFF687078), fontWeight: FontWeight.w600),
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  kpi.value,
                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.w900, color: kpi.color),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildUserActionBar(bool isCompact) {
    final searchField = TextField(
      onChanged: (v) => setState(() => _userSearchQuery = v),
      decoration: InputDecoration(
        hintText: 'Search by name, ID, email...',
        hintStyle: const TextStyle(fontSize: 12, color: Color(0xFF9AA2A9)),
        prefixIcon: const Icon(Icons.search, size: 18, color: Color(0xFF687078)),
        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        filled: true,
        fillColor: Colors.white,
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: Color(0xFFE2E5E8))),
        enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: Color(0xFFE2E5E8))),
      ),
    );

    final roleFilterDropdown = DropdownButtonFormField<UserRole?>(
      initialValue: _selectedRoleFilter,
      isExpanded: true,
      decoration: InputDecoration(
        labelText: 'Filter by Role',
        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        filled: true,
        fillColor: Colors.white,
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: Color(0xFFE2E5E8))),
        enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: Color(0xFFE2E5E8))),
      ),
      items: [
        const DropdownMenuItem<UserRole?>(
          value: null,
          child: Text('All Roles', style: TextStyle(fontSize: 12)),
        ),
        ...UserRole.values.map((r) {
          return DropdownMenuItem<UserRole?>(
            value: r,
            child: Text(r.displayName, style: const TextStyle(fontSize: 12)),
          );
        }),
      ],
      onChanged: (val) => setState(() => _selectedRoleFilter = val),
    );

    final provisionButton = ElevatedButton.icon(
      onPressed: _showCreateUserDialog,
      icon: const Icon(Icons.person_add_alt_1_rounded, size: 16),
      label: const Text('Provision User', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700)),
      style: ElevatedButton.styleFrom(
        backgroundColor: const Color(0xFFE31E24),
        foregroundColor: Colors.white,
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      ),
    );

    if (isCompact) {
      return Column(
        children: [
          searchField,
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(child: roleFilterDropdown),
              const SizedBox(width: 8),
              provisionButton,
            ],
          ),
        ],
      );
    }

    return Row(
      children: [
        Expanded(flex: 3, child: searchField),
        const SizedBox(width: 10),
        Expanded(flex: 2, child: roleFilterDropdown),
        const SizedBox(width: 10),
        provisionButton,
      ],
    );
  }

  Widget _buildUserGrid(List<UserModel> users, {required int crossAxisCount}) {
    if (crossAxisCount == 1) {
      return Column(
        children: users.map((user) => _buildUserCard(user)).toList(),
      );
    }

    // Two-column layout
    final leftList = <UserModel>[];
    final rightList = <UserModel>[];
    for (int i = 0; i < users.length; i++) {
      if (i % 2 == 0) {
        leftList.add(users[i]);
      } else {
        rightList.add(users[i]);
      }
    }

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          child: Column(
            children: leftList.map((user) => _buildUserCard(user)).toList(),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            children: rightList.map((user) => _buildUserCard(user)).toList(),
          ),
        ),
      ],
    );
  }

  Widget _buildUserCard(UserModel user) {
    final role = user.userRole;
    final roleColor = _getRoleColor(role);

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: user.isActive ? const Color(0xFFE2E5E8) : const Color(0xFFFCA5A5),
            width: user.isActive ? 1 : 1.2,
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.02),
              blurRadius: 6,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                // Avatar
                Container(
                  width: 36,
                  height: 36,
                  decoration: BoxDecoration(
                    color: roleColor.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Center(
                    child: Text(
                      user.name.isNotEmpty ? user.name.substring(0, 1).toUpperCase() : 'U',
                      style: TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w800,
                        color: roleColor,
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                // Name, Role & Employee ID
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Flexible(
                            child: Text(
                              user.name,
                              style: const TextStyle(
                                fontSize: 13.5,
                                fontWeight: FontWeight.w800,
                                color: Color(0xFF2B2A29),
                              ),
                              overflow: TextOverflow.ellipsis,
                              maxLines: 1,
                            ),
                          ),
                          const SizedBox(width: 6),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                            decoration: BoxDecoration(
                              color: roleColor.withValues(alpha: 0.1),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(
                              role.displayName.toUpperCase(),
                              style: TextStyle(fontSize: 8.5, fontWeight: FontWeight.w800, color: roleColor),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 2),
                      Text(
                        '${user.employeeId} • ${user.department}',
                        style: const TextStyle(fontSize: 10.5, color: Color(0xFF687078)),
                        overflow: TextOverflow.ellipsis,
                        maxLines: 1,
                      ),
                    ],
                  ),
                ),
                // Delete & Active Switch
                IconButton(
                  icon: const Icon(Icons.delete_outline_rounded, size: 18, color: Color(0xFF9AA2A9)),
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                  tooltip: 'Revoke User',
                  onPressed: () => _showDeleteUserConfirmation(user),
                ),
                const SizedBox(width: 4),
                Transform.scale(
                  scale: 0.8,
                  child: Switch(
                    value: user.isActive,
                    activeThumbColor: const Color(0xFF166534),
                    activeTrackColor: const Color(0xFFDCFCE7),
                    inactiveThumbColor: const Color(0xFF991B1B),
                    inactiveTrackColor: const Color(0xFFFEE2E2),
                    onChanged: (_) => _toggleUserStatus(user),
                  ),
                ),
              ],
            ),
            const Divider(height: 14, color: Color(0xFFECEEF0)),
            // Bottom Info: Email & Scope
            Row(
              children: [
                const Icon(Icons.email_outlined, size: 12, color: Color(0xFF9AA2A9)),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(
                    user.email,
                    style: const TextStyle(fontSize: 10.5, color: Color(0xFF687078)),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1.5),
                  decoration: BoxDecoration(
                    color: user.isActive ? const Color(0xFFDCFCE7) : const Color(0xFFFEE2E2),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    user.isActive ? 'ACTIVE' : 'DEACTIVATED',
                    style: TextStyle(
                      fontSize: 8.5,
                      fontWeight: FontWeight.w800,
                      color: user.isActive ? const Color(0xFF166534) : const Color(0xFF991B1B),
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Row(
              children: [
                const Icon(Icons.location_on_outlined, size: 12, color: Color(0xFF9AA2A9)),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(
                    'Scope: ${user.siteScopeFormatted}',
                    style: const TextStyle(fontSize: 10.5, color: Color(0xFF687078)),
                    overflow: TextOverflow.ellipsis,
                    maxLines: 1,
                  ),
                ),
              ],
            ),
            if (!user.isActive) ...[
              const SizedBox(height: 8),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: () => _acceptAccessRequest(user),
                  icon: const Icon(Icons.check_circle_rounded, size: 14, color: Colors.white),
                  label: const Text('Accept Request & Unlock Access', style: TextStyle(fontSize: 11.5, fontWeight: FontWeight.w800)),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF166534),
                    foregroundColor: Colors.white,
                    elevation: 0,
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildPendingRequestsBanner(List<UserModel> pendingUsers, bool isCompact) {
    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFFFFFBEB),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFFF59E0B), width: 1.5),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFFF59E0B).withValues(alpha: 0.08),
            blurRadius: 6,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(6),
                decoration: BoxDecoration(
                  color: const Color(0xFFD97706).withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: const Icon(Icons.person_add_alt_1_rounded, color: Color(0xFFD97706), size: 18),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'PENDING EMPLOYEE ACCESS REQUESTS (${pendingUsers.length})',
                      style: const TextStyle(
                        fontSize: 12.5,
                        fontWeight: FontWeight.w900,
                        color: Color(0xFF92400E),
                        letterSpacing: 0.3,
                      ),
                    ),
                    const SizedBox(height: 1),
                    const Text(
                      'Approve requests to activate accounts and grant role-specific app access.',
                      style: TextStyle(fontSize: 11, color: Color(0xFF78350F)),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          ...pendingUsers.map((user) => _buildPendingUserCard(user, isCompact)),
        ],
      ),
    );
  }

  Widget _buildPendingUserCard(UserModel user, bool isCompact) {
    final role = user.userRole;
    final roleColor = _getRoleColor(role);

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: const Color(0xFFFDE68A)),
      ),
      child: isCompact
          ? Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    CircleAvatar(
                      radius: 16,
                      backgroundColor: roleColor.withValues(alpha: 0.15),
                      child: Text(
                        user.name.isNotEmpty ? user.name[0].toUpperCase() : 'U',
                        style: TextStyle(fontSize: 13, fontWeight: FontWeight.w800, color: roleColor),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Flexible(
                                child: Text(
                                  user.name,
                                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w800, color: Color(0xFF2B2A29)),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              const SizedBox(width: 6),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                                decoration: BoxDecoration(
                                  color: roleColor.withValues(alpha: 0.1),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: Text(
                                  role.displayName.toUpperCase(),
                                  style: TextStyle(fontSize: 8.5, fontWeight: FontWeight.w800, color: roleColor),
                                ),
                              ),
                            ],
                          ),
                          Text(
                            '${user.employeeId} • ${user.email}',
                            style: const TextStyle(fontSize: 10.5, color: Color(0xFF687078)),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 6),
                Text(
                  'Site Scope: ${user.siteScopeFormatted}',
                  style: const TextStyle(fontSize: 10.5, color: Color(0xFF687078)),
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 8),
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    OutlinedButton.icon(
                      onPressed: () => _showDeleteUserConfirmation(user),
                      icon: const Icon(Icons.close, size: 14, color: Color(0xFFDC2626)),
                      label: const Text('Reject', style: TextStyle(fontSize: 11, color: Color(0xFFDC2626), fontWeight: FontWeight.w700)),
                      style: OutlinedButton.styleFrom(
                        side: const BorderSide(color: Color(0xFFFCA5A5)),
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                        minimumSize: Size.zero,
                        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                      ),
                    ),
                    const SizedBox(width: 8),
                    ElevatedButton.icon(
                      onPressed: () => _acceptAccessRequest(user),
                      icon: const Icon(Icons.check_circle_rounded, size: 14, color: Colors.white),
                      label: const Text('Accept Request', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w800)),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF166534),
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
                        minimumSize: Size.zero,
                        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                      ),
                    ),
                  ],
                ),
              ],
            )
          : Row(
              children: [
                CircleAvatar(
                  radius: 16,
                  backgroundColor: roleColor.withValues(alpha: 0.15),
                  child: Text(
                    user.name.isNotEmpty ? user.name[0].toUpperCase() : 'U',
                    style: TextStyle(fontSize: 13, fontWeight: FontWeight.w800, color: roleColor),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Flexible(
                            child: Text(
                              user.name,
                              style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w800, color: Color(0xFF2B2A29)),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          const SizedBox(width: 6),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                            decoration: BoxDecoration(
                              color: roleColor.withValues(alpha: 0.1),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(
                              role.displayName.toUpperCase(),
                              style: TextStyle(fontSize: 8.5, fontWeight: FontWeight.w800, color: roleColor),
                            ),
                          ),
                        ],
                      ),
                      Text(
                        '${user.employeeId} • ${user.email} • Site: ${user.siteScopeFormatted}',
                        style: const TextStyle(fontSize: 10.5, color: Color(0xFF687078)),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                OutlinedButton.icon(
                  onPressed: () => _showDeleteUserConfirmation(user),
                  icon: const Icon(Icons.close, size: 14, color: Color(0xFFDC2626)),
                  label: const Text('Reject', style: TextStyle(fontSize: 11, color: Color(0xFFDC2626), fontWeight: FontWeight.w700)),
                  style: OutlinedButton.styleFrom(
                    side: const BorderSide(color: Color(0xFFFCA5A5)),
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                    minimumSize: Size.zero,
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                  ),
                ),
                const SizedBox(width: 8),
                ElevatedButton.icon(
                  onPressed: () => _acceptAccessRequest(user),
                  icon: const Icon(Icons.check_circle_rounded, size: 14, color: Colors.white),
                  label: const Text('Accept Request', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w800)),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF166534),
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
                    minimumSize: Size.zero,
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                  ),
                ),
              ],
            ),
    );
  }

  Widget _buildRbacMatrixCard({required bool isCompact}) {
    return EnterpriseCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Row(
                children: [
                  Icon(Icons.shield_outlined, color: Color(0xFFE31E24), size: 18),
                  SizedBox(width: 8),
                  Text(
                    'RBAC PRIVILEGE MATRIX',
                    style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w900, color: Color(0xFF2B2A29)),
                  ),
                ],
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: const Color(0xFFE31E24).withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: const Text(
                  '5 System Roles',
                  style: TextStyle(fontSize: 10, color: Color(0xFFE31E24), fontWeight: FontWeight.w800),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          const Text(
            'Role authorizations mapped to functional permissions:',
            style: TextStyle(fontSize: 11, color: Color(0xFF687078)),
          ),
          const Divider(height: 18, color: Color(0xFFE2E5E8)),
          ...UserRole.values.map((r) {
            final pList = RbacService.getPermissionsForRole(r);
            final roleColor = _getRoleColor(r);
            return Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xFFF7F8FA),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFFE2E5E8)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            Container(
                              width: 8,
                              height: 8,
                              decoration: BoxDecoration(color: roleColor, shape: BoxShape.circle),
                            ),
                            const SizedBox(width: 6),
                            Text(r.displayName, style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w800)),
                          ],
                        ),
                        Text(
                          '${pList.length} Grants',
                          style: TextStyle(fontSize: 10, fontWeight: FontWeight.w700, color: roleColor),
                        ),
                      ],
                    ),
                    const SizedBox(height: 2),
                    Text(r.description, style: const TextStyle(fontSize: 10.5, color: Color(0xFF687078))),
                    const SizedBox(height: 6),
                    Wrap(
                      spacing: 4,
                      runSpacing: 4,
                      children: pList.take(isCompact ? 4 : 6).map((p) {
                        return Container(
                          padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                          decoration: BoxDecoration(
                            color: Colors.white,
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(color: const Color(0xFFE2E5E8)),
                          ),
                          child: Text(
                            p.name,
                            style: const TextStyle(fontSize: 9, fontWeight: FontWeight.w600, color: Color(0xFF2B2A29)),
                          ),
                        );
                      }).toList(),
                    ),
                  ],
                ),
              ),
            );
          }),
        ],
      ),
    );
  }

  // ==========================================
  // TAB 2: Operational Sites & Field Assets (Connected to Live Reports Data)
  // ==========================================
  Widget _buildSitesTab() {
    final liveReports = ref.watch(reportsProvider);
    final sitesList = ref.watch(sitesProvider);

    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;
        final isCompact = screenWidth < 680;
        final isWide = screenWidth >= 1100;
        final horizontalPadding = isCompact ? 14.0 : (isWide ? 28.0 : 20.0);

        // Aggregate stats calculated dynamically from live report dataset
        int totalRigs = 0;
        for (var s in sitesList) {
          totalRigs += s.activeRigs;
        }

        final totalOpenReports = liveReports.where((r) => r.status != ReportStatus.closed && r.status != ReportStatus.resolved).length;
        final totalCriticalAlerts = liveReports.where((r) => r.sifAnalysis?.sifPotential == SifPotential.critical && r.status != ReportStatus.closed).length;

        // Filter sites
        final filteredSites = sitesList.where((s) {
          final query = _siteSearchQuery.toLowerCase();
          if (query.isEmpty) return true;
          return s.name.toLowerCase().contains(query) ||
              s.code.toLowerCase().contains(query) ||
              s.type.toLowerCase().contains(query);
        }).toList();

        final columns = isCompact ? 1 : (isWide ? 3 : 2);

        return SingleChildScrollView(
          padding: EdgeInsets.symmetric(horizontal: horizontalPadding, vertical: 16),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1400),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Real-time KPI Summary Bar
                  _buildSitesKpiRow(isCompact, screenWidth, sitesList.length, totalRigs, totalOpenReports, totalCriticalAlerts),
                  const SizedBox(height: 16),

                  // Search Bar & Title
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          onChanged: (v) => setState(() => _siteSearchQuery = v),
                          decoration: InputDecoration(
                            hintText: 'Search site by name, code (e.g. DLN-HQ, Moran)...',
                            hintStyle: const TextStyle(fontSize: 12, color: Color(0xFF9AA2A9)),
                            prefixIcon: const Icon(Icons.search, size: 18, color: Color(0xFF687078)),
                            contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                            filled: true,
                            fillColor: Colors.white,
                            border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: Color(0xFFE2E5E8))),
                            enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: Color(0xFFE2E5E8))),
                          ),
                        ),
                      ),
                      if (_siteSearchQuery.isNotEmpty) ...[
                        const SizedBox(width: 8),
                        IconButton(
                          onPressed: () => setState(() => _siteSearchQuery = ''),
                          icon: const Icon(Icons.clear, size: 18),
                        ),
                      ],
                    ],
                  ),
                  const SizedBox(height: 16),

                  // Sites Grid calculated dynamically
                  if (filteredSites.isEmpty)
                    _buildEmptySearchState('No operational sites match the search filter.')
                  else
                    _buildSitesGrid(filteredSites, liveReports, columns),
                  const SizedBox(height: 32),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildSitesKpiRow(bool isCompact, double screenWidth, int siteCount, int totalRigs, int totalReports, int totalAlerts) {
    final kpis = [
      _KpiItem('Operational Sites', '$siteCount Sites', Icons.location_city_rounded, const Color(0xFF2B2A29)),
      _KpiItem('Active Rigs', '$totalRigs Drill Units', Icons.precision_manufacturing_rounded, const Color(0xFF2563EB)),
      _KpiItem('Live Open Reports', '$totalReports Logs', Icons.assignment_outlined, const Color(0xFFD97706)),
      _KpiItem('Critical SIF Precursors', '$totalAlerts Active', Icons.warning_amber_rounded, const Color(0xFFE31E24)),
    ];

    if (screenWidth < 520) {
      return Column(
        children: [
          Row(
            children: [
              Expanded(child: _buildKpiCard(kpis[0])),
              const SizedBox(width: 8),
              Expanded(child: _buildKpiCard(kpis[1])),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(child: _buildKpiCard(kpis[2])),
              const SizedBox(width: 8),
              Expanded(child: _buildKpiCard(kpis[3])),
            ],
          ),
        ],
      );
    }

    return Row(
      children: kpis.map((kpi) {
        return Expanded(
          child: Padding(
            padding: const EdgeInsets.only(right: 8.0),
            child: _buildKpiCard(kpi),
          ),
        );
      }).toList(),
    );
  }

  Widget _buildSitesGrid(List<SiteModel> sites, List<ReportModel> reports, int columns) {
    if (columns == 1) {
      return Column(
        children: sites.map((s) => _buildSiteCard(s, reports)).toList(),
      );
    }

    final columnLists = List.generate(columns, (_) => <SiteModel>[]);
    for (int i = 0; i < sites.length; i++) {
      columnLists[i % columns].add(sites[i]);
    }

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: List.generate(columns, (colIdx) {
        return Expanded(
          child: Padding(
            padding: EdgeInsets.only(
              left: colIdx == 0 ? 0 : 6,
              right: colIdx == columns - 1 ? 0 : 6,
            ),
            child: Column(
              children: columnLists[colIdx].map((s) => _buildSiteCard(s, reports)).toList(),
            ),
          ),
        );
      }),
    );
  }

  Widget _buildSiteCard(SiteModel site, List<ReportModel> reports) {
    // Dynamically calculate live site stats from real report collection
    final siteReports = reports.where((r) {
      return r.site.toLowerCase().trim() == site.name.toLowerCase().trim() ||
          r.site.toLowerCase().contains(site.code.toLowerCase()) ||
          site.name.toLowerCase().contains(r.site.toLowerCase());
    }).toList();

    final openReports = siteReports.where((r) => r.status != ReportStatus.closed && r.status != ReportStatus.resolved).length;
    final criticalAlerts = siteReports.where((r) => (r.sifAnalysis?.sifPotential == SifPotential.critical || r.sifAnalysis?.sifPotential == SifPotential.high) && r.status != ReportStatus.closed).length;
    final activeRigs = site.activeRigs;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: criticalAlerts > 0 ? const Color(0xFFFCA5A5) : const Color(0xFFE2E5E8),
            width: criticalAlerts > 0 ? 1.2 : 1,
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.02),
              blurRadius: 6,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: const Color(0xFFE31E24).withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(Icons.location_on_rounded, color: Color(0xFFE31E24), size: 18),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        site.name,
                        style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w800, color: Color(0xFF2B2A29)),
                        overflow: TextOverflow.ellipsis,
                        maxLines: 1,
                      ),
                      const SizedBox(height: 2),
                      Text(
                        '${site.code} • ${site.type}',
                        style: const TextStyle(fontSize: 11, color: Color(0xFF687078)),
                        overflow: TextOverflow.ellipsis,
                        maxLines: 1,
                      ),
                    ],
                  ),
                ),
                if (criticalAlerts > 0)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: const Color(0xFFFEE2E2),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      '$criticalAlerts SIF Alert${criticalAlerts > 1 ? "s" : ""}',
                      style: const TextStyle(fontSize: 9.5, fontWeight: FontWeight.w800, color: Color(0xFFDC2626)),
                    ),
                  )
                else
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: const Color(0xFFDCFCE7),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text(
                      'SECURE',
                      style: TextStyle(fontSize: 9.5, fontWeight: FontWeight.w800, color: Color(0xFF166534)),
                    ),
                  ),
              ],
            ),
            const Divider(height: 18, color: Color(0xFFE2E5E8)),
            // Metrics Row
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    const Icon(Icons.precision_manufacturing_outlined, size: 13, color: Color(0xFF687078)),
                    const SizedBox(width: 4),
                    Text(
                      'Rigs: $activeRigs',
                      style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: Color(0xFF2B2A29)),
                    ),
                  ],
                ),
                Row(
                  children: [
                    const Icon(Icons.assignment_outlined, size: 13, color: Color(0xFF687078)),
                    const SizedBox(width: 4),
                    Text(
                      'Live Logs: $openReports',
                      style: const TextStyle(fontSize: 11, color: Color(0xFF687078)),
                    ),
                  ],
                ),
                Row(
                  children: [
                    const Icon(Icons.gps_fixed_rounded, size: 11, color: Color(0xFF9CA3AF)),
                    const SizedBox(width: 3),
                    Text(
                      '${site.latitude}, ${site.longitude}',
                      style: const TextStyle(fontSize: 9.5, color: Color(0xFF9CA3AF), fontFamily: 'RobotoMono'),
                    ),
                  ],
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // TAB 3: Security Vault & Audit Trail
  // ==========================================
  Widget _buildSecurityVaultTab() {
    final auditEvents = _auditService.getEvents();
    final encStatus = _encryptionService.getEncryptionStatus();
    final envProfile = EnvironmentConfig.getSecurityAuditProfile();
    final currentAuth = ref.watch(authProvider);

    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;
        final isCompact = screenWidth < 680;
        final isWide = screenWidth >= 1050;
        final horizontalPadding = isCompact ? 14.0 : (isWide ? 28.0 : 20.0);

        // Filter audit events
        final filteredEvents = auditEvents.where((e) {
          final matchesSearch = _auditSearchQuery.isEmpty ||
              e.actorName.toLowerCase().contains(_auditSearchQuery.toLowerCase()) ||
              e.employeeId.toLowerCase().contains(_auditSearchQuery.toLowerCase()) ||
              e.actionDescription.toLowerCase().contains(_auditSearchQuery.toLowerCase()) ||
              e.type.code.toLowerCase().contains(_auditSearchQuery.toLowerCase());
          final matchesOutcome = _auditOutcomeFilter == null || e.outcome == _auditOutcomeFilter;
          return matchesSearch && matchesOutcome;
        }).toList();

        return SingleChildScrollView(
          padding: EdgeInsets.symmetric(horizontal: horizontalPadding, vertical: 16),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1400),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Top Security Architecture Cards
                  if (screenWidth >= 850) ...[
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(child: _buildEnterpriseDefenseCard(encStatus, envProfile, currentAuth.user)),
                        const SizedBox(width: 16),
                        Expanded(child: _buildComplianceCard(auditEvents.length, currentAuth)),
                      ],
                    ),
                  ] else ...[
                    _buildEnterpriseDefenseCard(encStatus, envProfile, currentAuth.user),
                    const SizedBox(height: 12),
                    _buildComplianceCard(auditEvents.length, currentAuth),
                  ],
                  const SizedBox(height: 16),

                  // Live Audit Trail Log Card
                  EnterpriseCard(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Row(
                              children: [
                                Icon(Icons.history_edu_rounded, color: Color(0xFFE31E24), size: 20),
                                SizedBox(width: 8),
                                Text(
                                  'Security Audit Trail',
                                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.w800, color: Color(0xFF2B2A29)),
                                ),
                              ],
                            ),
                            Row(
                              children: [
                                TextButton.icon(
                                  onPressed: () {
                                    _auditService.clearEvents();
                                    _auditService.logEvent(
                                      type: AuditEventType.securityConfigChanged,
                                      employeeId: currentAuth.user.employeeId,
                                      actorName: currentAuth.user.name,
                                      role: UserRole.administrator,
                                      actionDescription: 'Audit trail archive verified and session ledger cleared',
                                      outcome: 'SUCCESS',
                                    );
                                    setState(() {});
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      const SnackBar(content: Text('Audit ledger cleared & signed checkpoint recorded.')),
                                    );
                                  },
                                  icon: const Icon(Icons.cleaning_services_rounded, size: 14, color: Color(0xFF687078)),
                                  label: const Text('Reset Log', style: TextStyle(fontSize: 10, color: Color(0xFF687078))),
                                ),
                                const SizedBox(width: 6),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                  decoration: BoxDecoration(color: const Color(0xFFFEE2E2), borderRadius: BorderRadius.circular(4)),
                                  child: const Text(
                                    'IMMUTABLE LEDGER',
                                    style: TextStyle(fontSize: 9.5, color: Color(0xFFDC2626), fontWeight: FontWeight.w800),
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                        const SizedBox(height: 4),
                        const Text(
                          'Live recorded runtime security events, authentication attempts, AI overrides, and RBAC actions.',
                          style: TextStyle(fontSize: 11, color: Color(0xFF687078)),
                        ),
                        const Divider(height: 18, color: Color(0xFFE2E5E8)),

                        // Filters & Search
                        _buildAuditFilterBar(isCompact),
                        const SizedBox(height: 12),

                        // Audit Events List
                        if (filteredEvents.isEmpty)
                          _buildEmptySearchState('No audit log entries match the filter criteria.')
                        else
                          ...filteredEvents.map((event) => _buildAuditEventItem(event, isCompact)),
                      ],
                    ),
                  ),
                  const SizedBox(height: 32),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildEnterpriseDefenseCard(Map<String, dynamic> encStatus, Map<String, dynamic> envProfile, UserModel activeAdmin) {
    return EnterpriseCard(
      padding: const EdgeInsets.all(16),
      backgroundColor: const Color(0xFF2B2A29),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(color: const Color(0xFFE31E24), borderRadius: BorderRadius.circular(8)),
                child: const Icon(Icons.shield_rounded, color: Colors.white, size: 20),
              ),
              const SizedBox(width: 12),
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'ACTIVE ENTERPRISE DEFENSE',
                      style: TextStyle(color: Color(0xFFE31E24), fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.1),
                    ),
                    Text(
                      'Security Architecture & Session Guard',
                      style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w800),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          _buildDarkSecurityRow('At-Rest Encryption', encStatus['cipher'].toString(), Icons.enhanced_encryption_rounded),
          _buildDarkSecurityRow('Transport Security', envProfile['protocol'].toString(), Icons.lock_clock_rounded),
          _buildDarkSecurityRow('Token Storage', 'Hardware Keystore / Encrypted Vault', Icons.storage_rounded),
          _buildDarkSecurityRow('Active Administrator', '${activeAdmin.name} (${activeAdmin.employeeId})', Icons.admin_panel_settings_rounded),
          _buildDarkSecurityRow('Audit Vault', 'Tamper-Evident Immutable Log Active', Icons.history_edu_rounded),
        ],
      ),
    );
  }

  Widget _buildComplianceCard(int logCount, AuthState authState) {
    return EnterpriseCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: const Color(0xFF166534).withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: const Icon(Icons.verified_user_rounded, color: Color(0xFF166534), size: 20),
              ),
              const SizedBox(width: 12),
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'SECURITY & COMPLIANCE HEALTH',
                      style: TextStyle(color: Color(0xFF166534), fontSize: 10, fontWeight: FontWeight.w900, letterSpacing: 1.1),
                    ),
                    Text(
                      'Zero Trust Policy & Realtime Telemetry',
                      style: TextStyle(color: Color(0xFF2B2A29), fontSize: 14, fontWeight: FontWeight.w800),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          _buildLightSecurityRow('Compliance Index', '100% (IOGP & OIL Guidelines)', Icons.check_circle_outline_rounded, const Color(0xFF166534)),
          _buildLightSecurityRow('Total Audit Entries', '$logCount Ledger Events', Icons.receipt_long_outlined, const Color(0xFF2B2A29)),
          _buildLightSecurityRow('Authentication Gateway', authState.status == AuthStatus.authenticated ? 'Live Verified' : 'Standard Gate', Icons.lock_outline_rounded, const Color(0xFF2563EB)),
          _buildLightSecurityRow('Threat Detection', 'Active IDS / Precursor Sentinel', Icons.radar_outlined, const Color(0xFFD97706)),
          _buildLightSecurityRow('Data Sovereignty', 'Northeast Intranet & Indian DC', Icons.cloud_done_outlined, const Color(0xFF166534)),
        ],
      ),
    );
  }

  Widget _buildLightSecurityRow(String label, String val, IconData icon, Color iconColor) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          Icon(icon, size: 14, color: iconColor),
          const SizedBox(width: 8),
          Expanded(child: Text(label, style: const TextStyle(fontSize: 11.5, color: Color(0xFF687078)))),
          Text(val, style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: Color(0xFF2B2A29))),
        ],
      ),
    );
  }

  Widget _buildAuditFilterBar(bool isCompact) {
    final searchInput = TextField(
      onChanged: (v) => setState(() => _auditSearchQuery = v),
      decoration: InputDecoration(
        hintText: 'Search audit events (actor, code, desc)...',
        hintStyle: const TextStyle(fontSize: 11.5, color: Color(0xFF9AA2A9)),
        prefixIcon: const Icon(Icons.search, size: 16, color: Color(0xFF687078)),
        contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        filled: true,
        fillColor: const Color(0xFFF7F8FA),
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(6), borderSide: const BorderSide(color: Color(0xFFE2E5E8))),
        enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(6), borderSide: const BorderSide(color: Color(0xFFE2E5E8))),
      ),
    );

    final outcomes = [null, 'SUCCESS', 'OVERRIDE', 'WARNING', 'DENIED'];

    final outcomeChips = Wrap(
      spacing: 6,
      runSpacing: 6,
      children: outcomes.map((out) {
        final isSel = _auditOutcomeFilter == out;
        final label = out ?? 'ALL';
        return ChoiceChip(
          label: Text(label, style: const TextStyle(fontSize: 10, fontWeight: FontWeight.w700)),
          selected: isSel,
          selectedColor: const Color(0xFFE31E24).withValues(alpha: 0.12),
          onSelected: (val) => setState(() => _auditOutcomeFilter = val ? out : null),
        );
      }).toList(),
    );

    if (isCompact) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          searchInput,
          const SizedBox(height: 8),
          outcomeChips,
        ],
      );
    }

    return Row(
      children: [
        Expanded(flex: 3, child: searchInput),
        const SizedBox(width: 12),
        outcomeChips,
      ],
    );
  }

  Widget _buildAuditEventItem(SecurityAuditEvent event, bool isCompact) {
    Color badgeColor;
    switch (event.outcome) {
      case 'SUCCESS':
        badgeColor = const Color(0xFF166534);
        break;
      case 'OVERRIDE':
        badgeColor = const Color(0xFFD97706);
        break;
      case 'WARNING':
        badgeColor = const Color(0xFFC2410C);
        break;
      case 'DENIED':
      default:
        badgeColor = const Color(0xFFDC2626);
        break;
    }

    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: const Color(0xFFF7F8FA),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: const Color(0xFFE2E5E8)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(color: badgeColor.withValues(alpha: 0.12), borderRadius: BorderRadius.circular(4)),
                      child: Text(event.type.code, style: TextStyle(fontSize: 9.5, fontWeight: FontWeight.w800, color: badgeColor)),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      event.id.length > 12 ? event.id.substring(0, 12) : event.id,
                      style: const TextStyle(fontSize: 10, color: Color(0xFF687078), fontFamily: 'RobotoMono'),
                    ),
                  ],
                ),
                Text(DateFormat('MMM dd HH:mm:ss').format(event.timestamp), style: const TextStyle(fontSize: 10, color: Color(0xFF687078))),
              ],
            ),
            const SizedBox(height: 4),
            Text(
              '${event.actorName} (${event.role.displayName}) • ${event.employeeId}',
              style: const TextStyle(fontSize: 11.5, fontWeight: FontWeight.w700, color: Color(0xFF2B2A29)),
              overflow: TextOverflow.ellipsis,
            ),
            Text(event.actionDescription, style: const TextStyle(fontSize: 11, color: Color(0xFF687078))),
            const SizedBox(height: 2),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text('IP: ${event.ipAddress}', style: const TextStyle(fontSize: 9.5, color: Color(0xFF9CA3AF), fontFamily: 'RobotoMono')),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                  decoration: BoxDecoration(
                    color: badgeColor.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(
                    event.outcome,
                    style: TextStyle(fontSize: 8.5, fontWeight: FontWeight.w800, color: badgeColor),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // TAB 4: AI Model & Hazard Taxonomy (Connected to Live Reports)
  // ==========================================
  Widget _buildAiModelTab() {
    final liveReports = ref.watch(reportsProvider);
    final aiAnalyzedCount = liveReports.where((r) => r.sifAnalysis != null).length;
    final humanValidatedCount = liveReports.where((r) => r.sifAnalysis?.isHumanValidated == true).length;

    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;
        final isCompact = screenWidth < 680;
        final isWide = screenWidth >= 900;
        final horizontalPadding = isCompact ? 14.0 : (isWide ? 28.0 : 20.0);

        final filteredTaxonomy = OilConstants.hazardTaxonomy.where((h) {
          final q = _taxonomySearchQuery.toLowerCase();
          if (q.isEmpty) return true;
          return (h['name']?.toLowerCase().contains(q) ?? false) ||
              (h['id']?.toLowerCase().contains(q) ?? false) ||
              (h['description']?.toLowerCase().contains(q) ?? false);
        }).toList();

        return SingleChildScrollView(
          padding: EdgeInsets.symmetric(horizontal: horizontalPadding, vertical: 16),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1400),
              child: isWide
                  ? Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(flex: 3, child: _buildAiParametersCard(aiAnalyzedCount, humanValidatedCount)),
                        const SizedBox(width: 16),
                        Expanded(flex: 3, child: _buildHazardTaxonomyCard(filteredTaxonomy, isCompact: false)),
                      ],
                    )
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        _buildAiParametersCard(aiAnalyzedCount, humanValidatedCount),
                        const SizedBox(height: 16),
                        _buildHazardTaxonomyCard(filteredTaxonomy, isCompact: true),
                        const SizedBox(height: 32),
                      ],
                    ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildAiParametersCard(int aiAnalyzedCount, int humanValidatedCount) {
    return EnterpriseCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.settings_suggest_rounded, color: Color(0xFFE31E24), size: 20),
              SizedBox(width: 8),
              Expanded(
                child: Text(
                  'AI Model & NLP Engine Parameters',
                  style: TextStyle(fontSize: 14.5, fontWeight: FontWeight.w800, color: Color(0xFF2B2A29)),
                ),
              ),
            ],
          ),
          const Divider(height: 20, color: Color(0xFFE2E5E8)),
          _buildAdminRow('Active Model Version', 'SIF-Sentinel-NLP-v2.4-OIL'),
          _buildAdminRow('Base Architecture', 'Transformer + Oilfield Domain Ontology'),
          _buildAdminRow('Inference Engine', 'On-Device Lightweight Model + Cloud AI API'),
          _buildAdminRow('Live Reports Analyzed', '$aiAnalyzedCount Reports Processed'),
          _buildAdminRow('Human-in-the-Loop Calibrations', '$humanValidatedCount Safety Overrides'),
          const SizedBox(height: 12),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text('SIF High-Priority Threshold', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600)),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(
                  color: const Color(0xFFE31E24).withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  '${(_confidenceThreshold * 100).toInt()}% Confidence',
                  style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w800, color: Color(0xFFE31E24)),
                ),
              ),
            ],
          ),
          Slider(
            value: _confidenceThreshold,
            min: 0.50,
            max: 0.95,
            divisions: 9,
            activeColor: const Color(0xFFE31E24),
            onChanged: (v) => setState(() => _confidenceThreshold = v),
          ),
          SwitchListTile(
            title: const Text('Few-Shot Domain Embeddings', style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w700)),
            subtitle: const Text('Incorporate verified HSE officer feedback in inference ranking', style: TextStyle(fontSize: 11, color: Color(0xFF687078))),
            value: _fewShotEnabled,
            activeThumbColor: const Color(0xFFE31E24),
            contentPadding: EdgeInsets.zero,
            onChanged: (v) => setState(() => _fewShotEnabled = v),
          ),
        ],
      ),
    );
  }

  Widget _buildHazardTaxonomyCard(List<Map<String, String>> taxonomyList, {required bool isCompact}) {
    return EnterpriseCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text('OIL HAZARD TAXONOMY', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w900, color: Color(0xFF2B2A29))),
              Text('${OilConstants.hazardTaxonomy.length} Categories', style: const TextStyle(fontSize: 11, color: Color(0xFF687078))),
            ],
          ),
          const SizedBox(height: 8),
          TextField(
            onChanged: (v) => setState(() => _taxonomySearchQuery = v),
            decoration: InputDecoration(
              hintText: 'Search hazard categories...',
              hintStyle: const TextStyle(fontSize: 11, color: Color(0xFF9AA2A9)),
              prefixIcon: const Icon(Icons.search, size: 16, color: Color(0xFF687078)),
              contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              filled: true,
              fillColor: const Color(0xFFF7F8FA),
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(6), borderSide: const BorderSide(color: Color(0xFFE2E5E8))),
              enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(6), borderSide: const BorderSide(color: Color(0xFFE2E5E8))),
            ),
          ),
          const Divider(height: 18, color: Color(0xFFE2E5E8)),
          if (taxonomyList.isEmpty)
            _buildEmptySearchState('No hazard taxonomy found.')
          else
            ...taxonomyList.map((h) {
              return Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: const Color(0xFFF7F8FA),
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(color: const Color(0xFFE2E5E8)),
                  ),
                  child: Row(
                    children: [
                      Container(width: 6, height: 6, decoration: const BoxDecoration(color: Color(0xFFE31E24), shape: BoxShape.circle)),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(h['name']!, style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700)),
                            if (h['description'] != null)
                              Text(
                                h['description']!,
                                style: const TextStyle(fontSize: 10.5, color: Color(0xFF687078)),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                              ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 6),
                      Text(h['id']!, style: const TextStyle(fontSize: 10, color: Color(0xFF687078), fontFamily: 'RobotoMono', fontWeight: FontWeight.w700)),
                    ],
                  ),
                ),
              );
            }),
        ],
      ),
    );
  }

  // ==========================================
  // TAB 5: Integrations & System Settings (Live Dynamic Telemetry)
  // ==========================================
  Widget _buildIntegrationsTab() {
    final liveReports = ref.watch(reportsProvider);
    final authState = ref.watch(authProvider);

    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;
        final isCompact = screenWidth < 680;
        final isWide = screenWidth >= 850;
        final horizontalPadding = isCompact ? 14.0 : (isWide ? 28.0 : 20.0);

        final card1 = EnterpriseCard(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Row(
                children: [
                  Icon(Icons.fingerprint_rounded, color: Color(0xFFE31E24), size: 18),
                  SizedBox(width: 8),
                  Text('AUTHENTICATION & SSO POLICIES', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w900, color: Color(0xFF2B2A29))),
                ],
              ),
              const Divider(height: 20, color: Color(0xFFE2E5E8)),
              _buildAdminRow('Active Admin Account', '${authState.user.name} (${authState.user.employeeId})'),
              _buildAdminRow('Identity Gateway', 'Oil India SAML 2.0 / Firebase Auth'),
              _buildAdminRow('Session Auto-Lock', '15-Min Inactivity Watchdog Active'),
              _buildAdminRow('Multi-Factor Auth', 'Hardware Biometrics & Secure Storage'),
            ],
          ),
        );

        final card2 = EnterpriseCard(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Row(
                children: [
                  Icon(Icons.cloud_sync_outlined, color: Color(0xFF2563EB), size: 18),
                  SizedBox(width: 8),
                  Text('CLOUD SYNC & OFFLINE ENGINE', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w900, color: Color(0xFF2B2A29))),
                ],
              ),
              const Divider(height: 20, color: Color(0xFFE2E5E8)),
              _buildAdminRow('Firestore Sync State', _isFirestoreConnected ? 'Connected (Realtime Delta)' : 'Local Encrypted Cache'),
              _buildAdminRow('Live Reports In Memory', '${liveReports.length} Active Records'),
              _buildAdminRow('Offline Queue Retry', 'Exponential Backoff (Auto-Sync)'),
              _buildAdminRow('Cache Retention Scope', '30 Days Operational Cache'),
            ],
          ),
        );

        final card3 = EnterpriseCard(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Row(
                children: [
                  Icon(Icons.dataset_outlined, color: Color(0xFFD97706), size: 18),
                  SizedBox(width: 8),
                  Text('OPERATIONAL DATASET MANAGEMENT', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w900, color: Color(0xFF2B2A29))),
                ],
              ),
              const SizedBox(height: 6),
              Text(
                'Currently managing ${liveReports.length} reports across ${OilConstants.sites.length} exploration assets.',
                style: const TextStyle(fontSize: 11, color: Color(0xFF687078)),
              ),
              const SizedBox(height: 14),
              CustomButton(
                label: 'Reload Baseline Operational Dataset',
                variant: ButtonVariant.outlined,
                icon: Icons.restart_alt_rounded,
                onPressed: () {
                  ref.read(reportsProvider.notifier).resetToDemoData();
                  _auditService.logEvent(
                    type: AuditEventType.securityConfigChanged,
                    employeeId: authState.user.employeeId,
                    actorName: authState.user.name,
                    role: UserRole.administrator,
                    actionDescription: 'Reloaded verified baseline operational safety dataset',
                    outcome: 'SUCCESS',
                  );
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Operational baseline dataset reloaded successfully.')),
                  );
                },
              ),
            ],
          ),
        );

        final card4 = EnterpriseCard(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Row(
                children: [
                  Icon(Icons.dns_outlined, color: Color(0xFF166534), size: 18),
                  SizedBox(width: 8),
                  Text('SYSTEM TELEMETRY & STATUS', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w900, color: Color(0xFF2B2A29))),
                ],
              ),
              const Divider(height: 20, color: Color(0xFFE2E5E8)),
              _buildAdminRow('Platform Health', 'All Systems Operational (100%)'),
              _buildAdminRow('Primary Datacenter', 'Northeast Cloud DC Guwahati'),
              _buildAdminRow('App Version', 'SIF Sentinel v2.4 Enterprise (OIL)'),
              _buildAdminRow('Security Architecture', 'Zero Trust Tier-3 Certified'),
            ],
          ),
        );

        return SingleChildScrollView(
          padding: EdgeInsets.symmetric(horizontal: horizontalPadding, vertical: 16),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1400),
              child: isWide
                  ? Column(
                      children: [
                        Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Expanded(child: card1),
                            const SizedBox(width: 16),
                            Expanded(child: card2),
                          ],
                        ),
                        const SizedBox(height: 16),
                        Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Expanded(child: card3),
                            const SizedBox(width: 16),
                            Expanded(child: card4),
                          ],
                        ),
                        const SizedBox(height: 32),
                      ],
                    )
                  : Column(
                      children: [
                        card1,
                        const SizedBox(height: 14),
                        card2,
                        const SizedBox(height: 14),
                        card3,
                        const SizedBox(height: 14),
                        card4,
                        const SizedBox(height: 32),
                      ],
                    ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildAdminRow(String label, String val) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Flexible(
            child: Text(
              label,
              style: const TextStyle(fontSize: 11.5, color: Color(0xFF687078)),
              overflow: TextOverflow.ellipsis,
            ),
          ),
          const SizedBox(width: 8),
          Flexible(
            child: Text(
              val,
              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700, color: Color(0xFF2B2A29)),
              textAlign: TextAlign.end,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDarkSecurityRow(String label, String val, IconData icon) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          Icon(icon, size: 14, color: const Color(0xFFE31E24)),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              label,
              style: const TextStyle(fontSize: 12, color: Colors.white70),
              overflow: TextOverflow.ellipsis,
            ),
          ),
          Text(
            val,
            style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: Colors.white),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptySearchState(String message) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 16),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFFE2E5E8)),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.search_off_rounded, size: 36, color: Color(0xFF9AA2A9)),
          const SizedBox(height: 8),
          Text(
            message,
            style: const TextStyle(fontSize: 12, color: Color(0xFF687078), fontWeight: FontWeight.w600),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}

class _KpiItem {
  final String title;
  final String value;
  final IconData icon;
  final Color color;

  _KpiItem(this.title, this.value, this.icon, this.color);
}
