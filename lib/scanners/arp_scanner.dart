import 'dart:io';
import 'dart:async';
import 'base_scanner.dart';

/// ARP表扫描器
class ArpScanner extends BaseScanner {
  ArpScanner({ScannerConfig? config})
    : super(
        name: 'ARP表扫描器',
        scanType: ScanResultType.arpTable,
        config: config ?? const ScannerConfig(),
      );

  @override
  String get description => '读取系统ARP表获取局域网内设备的MAC地址信息';

  @override
  int get priority => 3; // 中等优先级

  @override
  Future<bool> isAvailable() async {
    try {
      // 检查是否能执行arp命令
      final result = await Process.run('arp', [
        '-a',
      ]).timeout(const Duration(seconds: 2));
      return result.exitCode == 0;
    } catch (e) {
      return false;
    }
  }

  @override
  Future<ScanResult?> scanSingle(
    String ip,
    String networkSegment, {
    ScanProgressCallback? onProgress,
  }) async {
    try {
      final stopwatch = Stopwatch()..start();

      // 首先尝试ping目标IP以确保它在ARP表中
      await _ensureArpEntry(ip);

      // 读取ARP表
      final arpInfo = await _getArpInfo(ip);

      stopwatch.stop();

      if (arpInfo != null) {
        return ScanResult(
          ip: ip,
          isActive: true,
          responseTime: stopwatch.elapsedMilliseconds,
          networkSegment: networkSegment,
          detectionMethod: ScanResultType.arpTable,
          macAddress: arpInfo['mac'],
          additionalInfo: {
            'arp_status': arpInfo['status'],
            'interface': arpInfo['interface'],
            'vendor': await _getMacVendor(arpInfo['mac']),
          },
        );
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 确保目标IP在ARP表中（通过ping）
  Future<void> _ensureArpEntry(String ip) async {
    try {
      await Process.run('ping', [
        '-c',
        '1',
        '-t',
        '1',
        ip,
      ]).timeout(const Duration(seconds: 2));
    } catch (e) {
      // 忽略ping失败
    }
  }

  /// 从ARP表获取IP信息
  Future<Map<String, String>?> _getArpInfo(String ip) async {
    try {
      final result = await Process.run('arp', [
        '-n',
        ip,
      ]).timeout(const Duration(seconds: 2));

      if (result.exitCode == 0) {
        final output = result.stdout.toString();
        final lines = output.split('\n');

        for (final line in lines) {
          if (line.contains(ip)) {
            // 解析ARP表输出
            // 格式通常是: IP (IP) at MAC [ether] on interface
            final parts = line.split(RegExp(r'\s+'));

            for (int i = 0; i < parts.length; i++) {
              if (parts[i].contains(':') && parts[i].length == 17) {
                // 找到MAC地址
                final mac = parts[i];
                String status = 'static';
                String interface = 'unknown';

                // 尝试提取接口信息
                if (i + 2 < parts.length && parts[i + 1] == 'on') {
                  interface = parts[i + 2];
                }

                // 检查是否是动态条目
                if (line.contains('dynamic')) {
                  status = 'dynamic';
                }

                return {'mac': mac, 'status': status, 'interface': interface};
              }
            }
          }
        }
      }

      // 如果单个IP查询失败，尝试查询整个ARP表
      return await _searchInFullArpTable(ip);
    } catch (e) {
      return null;
    }
  }

  /// 在完整ARP表中搜索IP
  Future<Map<String, String>?> _searchInFullArpTable(String ip) async {
    try {
      final result = await Process.run('arp', [
        '-a',
      ]).timeout(const Duration(seconds: 3));

      if (result.exitCode == 0) {
        final output = result.stdout.toString();
        final lines = output.split('\n');

        for (final line in lines) {
          if (line.contains(ip)) {
            // 解析格式: hostname (IP) at MAC on interface
            final macMatch = RegExp(
              r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})',
            ).firstMatch(line);
            final interfaceMatch = RegExp(r'on (\w+)').firstMatch(line);

            if (macMatch != null) {
              return {
                'mac': macMatch.group(1)!,
                'status': line.contains('permanent') ? 'permanent' : 'dynamic',
                'interface': interfaceMatch?.group(1) ?? 'unknown',
              };
            }
          }
        }
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 获取MAC地址厂商信息
  Future<String?> _getMacVendor(String? macAddress) async {
    if (macAddress == null || macAddress.length < 8) {
      return null;
    }

    try {
      // 提取OUI (前3个字节，去除分隔符)
      final oui = macAddress.substring(0, 8).replaceAll(':', '').toUpperCase();

      // OUI厂商数据库 (使用6位十六进制字符串作为key，更高效)
      final ouiVendors = {
        '001B63': 'Apple',
        '002500': 'Apple',
        '002608': 'Apple',
        '3C15C2': 'Apple',
        '005056': 'VMware',
        '000C29': 'VMware',
        '080027': 'VirtualBox',
        '00155D': 'Microsoft',
        '001C42': 'Parallels',
        '00E04C': 'Realtek',
        '001AA0': 'Netgear',
        '002401': 'D-Link',
        '00265A': 'Linksys',
        // 添加更多常见厂商
        '001122': 'Cisco',
        '00D0C9': 'Intel',
        '001CF0': 'Dell',
        '002564': 'HP',
        '00A0C9': 'Intel',
        '001E58': 'WD (Western Digital)',
        '001B21': 'Intel',
      };

      // 直接使用OUI进行精确匹配，更高效
      final vendor = ouiVendors[oui];
      return vendor ?? 'Unknown';
    } catch (e) {
      return null;
    }
  }

  /// 批量扫描优化：一次性获取所有ARP表条目
  @override
  Future<List<ScanResult>> scanBatch(
    List<String> ips,
    String networkSegment, {
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  }) async {
    if (!config.enabled || !await isAvailable()) {
      return [];
    }

    try {
      final stopwatch = Stopwatch()..start();
      final results = <ScanResult>[];

      // 首先ping所有IP以填充ARP表
      final pingFutures = ips.map((ip) => _ensureArpEntry(ip)).toList();
      await Future.wait(pingFutures);

      // 一次性获取完整ARP表
      final arpTable = await _getFullArpTable();

      stopwatch.stop();

      // 匹配IP地址
      for (int i = 0; i < ips.length; i++) {
        final ip = ips[i];
        onProgress?.call(ip, i / ips.length);

        final arpInfo = arpTable[ip];
        if (arpInfo != null) {
          final result = ScanResult(
            ip: ip,
            isActive: true,
            responseTime: stopwatch.elapsedMilliseconds ~/ ips.length,
            networkSegment: networkSegment,
            detectionMethod: ScanResultType.arpTable,
            macAddress: arpInfo['mac'],
            additionalInfo: {
              'arp_status': arpInfo['status'],
              'interface': arpInfo['interface'],
              'vendor': await _getMacVendor(arpInfo['mac']),
            },
          );
          results.add(result);
          onResult?.call(result);
        }
      }

      return results;
    } catch (e) {
      return [];
    }
  }

  /// 获取完整ARP表
  Future<Map<String, Map<String, String>>> _getFullArpTable() async {
    final arpTable = <String, Map<String, String>>{};

    try {
      final result = await Process.run('arp', [
        '-a',
      ]).timeout(const Duration(seconds: 5));

      if (result.exitCode == 0) {
        final output = result.stdout.toString();
        final lines = output.split('\n');

        for (final line in lines) {
          final ipMatch = RegExp(
            r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)',
          ).firstMatch(line);
          final macMatch = RegExp(
            r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})',
          ).firstMatch(line);
          final interfaceMatch = RegExp(r'on (\w+)').firstMatch(line);

          if (ipMatch != null && macMatch != null) {
            final ip = ipMatch.group(1)!;
            arpTable[ip] = {
              'mac': macMatch.group(1)!,
              'status': line.contains('permanent') ? 'permanent' : 'dynamic',
              'interface': interfaceMatch?.group(1) ?? 'unknown',
            };
          }
        }
      }
    } catch (e) {
      // 返回空表
    }

    return arpTable;
  }
}
