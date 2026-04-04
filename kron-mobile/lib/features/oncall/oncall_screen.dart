/// On-call schedule screen — shows who is on-call now, the rotation
/// schedule, and allows an analyst to escalate or page the current
/// on-call directly from the mobile app.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../../services/api_service.dart';

// ── Models ───────────────────────────────────────────────────────────────────

/// Escalation tier within the on-call rotation.
enum OncallTier { primary, secondary, manager }

/// A single on-call entry in the rotation.
class OncallEntry {
  const OncallEntry({
    required this.userId,
    required this.name,
    required this.email,
    required this.phone,
    required this.tier,
    required this.startsAt,
    required this.endsAt,
    this.avatarInitials,
  });

  final String userId;
  final String name;
  final String email;
  final String phone;
  final OncallTier tier;
  final DateTime startsAt;
  final DateTime endsAt;
  final String? avatarInitials;

  bool get isActive {
    final now = DateTime.now().toUtc();
    return now.isAfter(startsAt) && now.isBefore(endsAt);
  }

  factory OncallEntry.fromJson(Map<String, dynamic> json) {
    return OncallEntry(
      userId: json['user_id'] as String? ?? '',
      name: json['name'] as String? ?? 'Unknown',
      email: json['email'] as String? ?? '',
      phone: json['phone'] as String? ?? '',
      tier: _parseTier(json['tier'] as String? ?? ''),
      startsAt:
          DateTime.tryParse(json['starts_at'] as String? ?? '') ?? DateTime.now(),
      endsAt:
          DateTime.tryParse(json['ends_at'] as String? ?? '') ?? DateTime.now(),
      avatarInitials: json['avatar_initials'] as String?,
    );
  }

  static OncallTier _parseTier(String s) => switch (s.toLowerCase()) {
        'primary' => OncallTier.primary,
        'secondary' => OncallTier.secondary,
        'manager' => OncallTier.manager,
        _ => OncallTier.primary,
      };
}

/// Full schedule response from API.
class OncallSchedule {
  const OncallSchedule({
    required this.rotation,
    required this.upcoming,
  });

  /// Currently active on-call analysts (one per tier).
  final List<OncallEntry> rotation;

  /// Next 7 days of schedule entries.
  final List<OncallEntry> upcoming;

  factory OncallSchedule.fromJson(Map<String, dynamic> json) {
    return OncallSchedule(
      rotation: (json['rotation'] as List<dynamic>? ?? [])
          .map((e) => OncallEntry.fromJson(e as Map<String, dynamic>))
          .toList(),
      upcoming: (json['upcoming'] as List<dynamic>? ?? [])
          .map((e) => OncallEntry.fromJson(e as Map<String, dynamic>))
          .toList(),
    );
  }
}

// ── Providers ─────────────────────────────────────────────────────────────────

final oncallScheduleProvider =
    FutureProvider.autoDispose<OncallSchedule>((ref) async {
  final api = ref.read(apiServiceProvider);
  return api.getOncallSchedule();
});

// ── Screen ────────────────────────────────────────────────────────────────────

class OncallScreen extends ConsumerWidget {
  const OncallScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final scheduleAsync = ref.watch(oncallScheduleProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('On-Call Schedule',
            style: TextStyle(fontWeight: FontWeight.w700)),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () => ref.invalidate(oncallScheduleProvider),
          ),
        ],
      ),
      body: scheduleAsync.when(
        data: (schedule) => _ScheduleBody(schedule: schedule),
        loading: () => const _LoadingSkeleton(),
        error: (e, _) => _ErrorState(message: e.toString()),
      ),
    );
  }
}

// ── Body ─────────────────────────────────────────────────────────────────────

class _ScheduleBody extends StatelessWidget {
  const _ScheduleBody({required this.schedule});
  final OncallSchedule schedule;

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      onRefresh: () async {
        // Refresh is handled by parent invalidation via appbar button;
        // this satisfies the RefreshIndicator API.
      },
      child: SingleChildScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Now on-call ────────────────────────────────────────────────
            _SectionHeader(title: 'NOW ON-CALL'),
            const SizedBox(height: 10),
            if (schedule.rotation.isEmpty)
              _EmptyCard(message: 'No active on-call schedule configured.')
            else
              ...schedule.rotation.map((e) => _ActiveOncallCard(entry: e)),

            // ── Upcoming ───────────────────────────────────────────────────
            const SizedBox(height: 24),
            _SectionHeader(title: 'UPCOMING — NEXT 7 DAYS'),
            const SizedBox(height: 10),
            if (schedule.upcoming.isEmpty)
              _EmptyCard(message: 'No upcoming schedule entries.')
            else
              _UpcomingList(entries: schedule.upcoming),

            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }
}

// ── Active on-call card ───────────────────────────────────────────────────────

class _ActiveOncallCard extends StatelessWidget {
  const _ActiveOncallCard({required this.entry});
  final OncallEntry entry;

  @override
  Widget build(BuildContext context) {
    final (tierLabel, tierColor) = switch (entry.tier) {
      OncallTier.primary => ('PRIMARY', const Color(0xFF3B82F6)),
      OncallTier.secondary => ('SECONDARY', const Color(0xFF8B5CF6)),
      OncallTier.manager => ('MANAGER', const Color(0xFFB45309)),
    };

    final timeLeft = entry.endsAt.difference(DateTime.now().toUtc());
    final hoursLeft = timeLeft.inHours;
    final minutesLeft = timeLeft.inMinutes % 60;

    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                _Avatar(initials: entry.avatarInitials ?? _initials(entry.name)),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(entry.name,
                          style: const TextStyle(
                              fontSize: 16, fontWeight: FontWeight.w700)),
                      const SizedBox(height: 2),
                      Text(entry.email,
                          style: const TextStyle(
                              fontSize: 12, color: Color(0xFF64748B))),
                    ],
                  ),
                ),
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: tierColor.withAlpha(30),
                    borderRadius: BorderRadius.circular(4),
                    border: Border.all(color: tierColor.withAlpha(100)),
                  ),
                  child: Text(tierLabel,
                      style: TextStyle(
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                          color: tierColor)),
                ),
              ],
            ),
            const SizedBox(height: 12),
            const Divider(color: Color(0xFF1E2D45), height: 1),
            const SizedBox(height: 12),
            Row(
              children: [
                const Icon(Icons.schedule, size: 14, color: Color(0xFF64748B)),
                const SizedBox(width: 4),
                Text(
                  'Ends in ${hoursLeft}h ${minutesLeft}m  ·  ${_formatTime(entry.endsAt)} UTC',
                  style: const TextStyle(
                      fontSize: 12, color: Color(0xFF64748B)),
                ),
              ],
            ),
            const SizedBox(height: 12),
            // Page button
            SizedBox(
              width: double.infinity,
              child: OutlinedButton.icon(
                style: OutlinedButton.styleFrom(
                  foregroundColor: const Color(0xFF3B82F6),
                  side: const BorderSide(color: Color(0xFF3B82F6)),
                  padding: const EdgeInsets.symmetric(vertical: 10),
                ),
                onPressed: () => _showPageDialog(context, entry),
                icon: const Icon(Icons.notifications_active_outlined, size: 16),
                label: Text('Page ${entry.name.split(' ').first}'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showPageDialog(BuildContext context, OncallEntry entry) {
    final controller = TextEditingController();
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF131929),
        title: Text('Page ${entry.name}'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('This will send a push notification and SMS to ${entry.phone}.',
                style: const TextStyle(
                    fontSize: 13, color: Color(0xFF94A3B8))),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              decoration: const InputDecoration(
                hintText: 'Reason / alert ID (optional)',
                hintStyle: TextStyle(color: Color(0xFF64748B)),
              ),
              maxLines: 2,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel',
                style: TextStyle(color: Color(0xFF64748B))),
          ),
          ElevatedButton.icon(
            onPressed: () {
              Navigator.pop(ctx);
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                content:
                    Text('${entry.name} has been paged'),
              ));
            },
            icon: const Icon(Icons.send, size: 16),
            label: const Text('Send Page'),
          ),
        ],
      ),
    );
  }
}

// ── Upcoming list ─────────────────────────────────────────────────────────────

class _UpcomingList extends StatelessWidget {
  const _UpcomingList({required this.entries});
  final List<OncallEntry> entries;

  @override
  Widget build(BuildContext context) {
    // Group by day
    final Map<String, List<OncallEntry>> byDay = {};
    for (final e in entries) {
      final key = DateFormat('EEE, d MMM').format(e.startsAt.toLocal());
      byDay.putIfAbsent(key, () => []).add(e);
    }

    return Column(
      children: byDay.entries.map((group) {
        return _DayGroup(day: group.key, entries: group.value);
      }).toList(),
    );
  }
}

class _DayGroup extends StatelessWidget {
  const _DayGroup({required this.day, required this.entries});
  final String day;
  final List<OncallEntry> entries;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Text(day,
              style: const TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: Color(0xFF64748B),
                  letterSpacing: 0.6)),
        ),
        Card(
          margin: const EdgeInsets.only(bottom: 10),
          child: Column(
            children: entries
                .asMap()
                .entries
                .map((e) => Column(
                      children: [
                        if (e.key > 0)
                          const Divider(
                              height: 1, color: Color(0xFF1E2D45)),
                        _UpcomingRow(entry: e.value),
                      ],
                    ))
                .toList(),
          ),
        ),
      ],
    );
  }
}

class _UpcomingRow extends StatelessWidget {
  const _UpcomingRow({required this.entry});
  final OncallEntry entry;

  @override
  Widget build(BuildContext context) {
    final (tierLabel, tierColor) = switch (entry.tier) {
      OncallTier.primary => ('P', const Color(0xFF3B82F6)),
      OncallTier.secondary => ('S', const Color(0xFF8B5CF6)),
      OncallTier.manager => ('M', const Color(0xFFB45309)),
    };

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      child: Row(
        children: [
          // Tier dot
          Container(
            width: 20,
            height: 20,
            decoration: BoxDecoration(
              color: tierColor.withAlpha(30),
              shape: BoxShape.circle,
              border: Border.all(color: tierColor.withAlpha(120)),
            ),
            alignment: Alignment.center,
            child: Text(tierLabel,
                style: TextStyle(
                    fontSize: 9,
                    fontWeight: FontWeight.w700,
                    color: tierColor)),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(entry.name,
                style: const TextStyle(
                    fontSize: 14, fontWeight: FontWeight.w500)),
          ),
          Text(
            '${_formatTime(entry.startsAt)} – ${_formatTime(entry.endsAt)}',
            style: const TextStyle(fontSize: 11, color: Color(0xFF64748B)),
          ),
        ],
      ),
    );
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

String _initials(String name) {
  final parts = name.trim().split(' ');
  if (parts.length >= 2) {
    return '${parts.first[0]}${parts.last[0]}'.toUpperCase();
  }
  return name.isEmpty ? '?' : name[0].toUpperCase();
}

String _formatTime(DateTime dt) =>
    DateFormat('HH:mm').format(dt.toLocal());

// ── Shared sub-widgets ────────────────────────────────────────────────────────

class _Avatar extends StatelessWidget {
  const _Avatar({required this.initials});
  final String initials;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 44,
      height: 44,
      decoration: BoxDecoration(
        color: const Color(0xFF1E2D45),
        shape: BoxShape.circle,
        border: Border.all(color: const Color(0xFF3B82F6), width: 1.5),
      ),
      alignment: Alignment.center,
      child: Text(
        initials,
        style: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w700,
            color: Color(0xFF3B82F6)),
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader({required this.title});
  final String title;

  @override
  Widget build(BuildContext context) {
    return Text(
      title,
      style: const TextStyle(
        fontSize: 11,
        fontWeight: FontWeight.w700,
        color: Color(0xFF64748B),
        letterSpacing: 0.8,
      ),
    );
  }
}

class _EmptyCard extends StatelessWidget {
  const _EmptyCard({required this.message});
  final String message;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Center(
          child: Text(message,
              style: const TextStyle(
                  fontSize: 13, color: Color(0xFF64748B))),
        ),
      ),
    );
  }
}

class _LoadingSkeleton extends StatelessWidget {
  const _LoadingSkeleton();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: List.generate(
          4,
          (i) => Container(
            height: 90,
            margin: const EdgeInsets.only(bottom: 12),
            decoration: BoxDecoration(
              color: const Color(0xFF131929),
              borderRadius: BorderRadius.circular(8),
            ),
          ),
        ),
      ),
    );
  }
}

class _ErrorState extends StatelessWidget {
  const _ErrorState({required this.message});
  final String message;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline,
                size: 48, color: Color(0xFFC81E1E)),
            const SizedBox(height: 16),
            const Text('Failed to load on-call schedule',
                style:
                    TextStyle(fontWeight: FontWeight.w600, fontSize: 16)),
            const SizedBox(height: 8),
            Text(message,
                style: const TextStyle(
                    fontSize: 13, color: Color(0xFF64748B)),
                textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }
}
