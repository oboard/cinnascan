import 'dart:io';
import 'dart:async';
import 'base_scanner.dart';

/// DNS反向解析扫描器
class DnsScanner extends BaseScanner {
  DnsScanner({ScannerConfig? config})
    : super(
        name: 'DNS反向解析扫描器',
        scanType: ScanResultType.dnsReverse,
        config: config ?? const ScannerConfig(),
      );

  @override
  String get description => '通过DNS反向解析获取设备主机名';

  @override
  int get priority => 2; // 较低优先级，作为补充信息

  @override
  Future<bool> isAvailable() async {
    try {
      // 测试DNS解析是否可用
      await InternetAddress.lookup('google.com');
      return true;
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

      // 执行反向DNS查询
      final hostInfo = await _performReverseLookup(ip);

      stopwatch.stop();

      if (hostInfo != null) {
        return ScanResult(
          ip: ip,
          isActive: true,
          responseTime: stopwatch.elapsedMilliseconds,
          networkSegment: networkSegment,
          detectionMethod: ScanResultType.dnsReverse,
          hostname: hostInfo['hostname'],
          additionalInfo: {
            'dns_available': true,
            'domain': hostInfo['domain'],
            'device_type': hostInfo['deviceType'],
            'is_local': hostInfo['isLocal'],
          },
        );
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 执行反向DNS查询
  Future<Map<String, dynamic>?> _performReverseLookup(String ip) async {
    try {
      // 使用系统DNS进行反向查询
      final result = await InternetAddress(ip).reverse();
      final hostname = result.host;

      if (hostname != ip && hostname.isNotEmpty) {
        // 成功获取主机名
        final domain = _extractDomain(hostname);
        final deviceType = _identifyDeviceType(hostname);
        final isLocal = _isLocalDomain(hostname);

        return {
          'hostname': hostname,
          'domain': domain,
          'deviceType': deviceType,
          'isLocal': isLocal,
        };
      }

      // 如果系统DNS失败，尝试其他方法
      return await _tryAlternativeDnsLookup(ip);
    } catch (e) {
      // 尝试其他DNS服务器
      return await _tryAlternativeDnsLookup(ip);
    }
  }

  /// 尝试其他DNS查询方法
  Future<Map<String, dynamic>?> _tryAlternativeDnsLookup(String ip) async {
    try {
      // 尝试使用nslookup命令
      final result = await Process.run('nslookup', [
        ip,
      ]).timeout(const Duration(seconds: 3));

      if (result.exitCode == 0) {
        final output = result.stdout.toString();
        final hostname = _parseNslookupOutput(output);

        if (hostname != null && hostname != ip) {
          final domain = _extractDomain(hostname);
          final deviceType = _identifyDeviceType(hostname);
          final isLocal = _isLocalDomain(hostname);

          return {
            'hostname': hostname,
            'domain': domain,
            'deviceType': deviceType,
            'isLocal': isLocal,
          };
        }
      }

      // 尝试使用dig命令
      return await _tryDigLookup(ip);
    } catch (e) {
      return null;
    }
  }

  /// 尝试使用dig命令
  Future<Map<String, dynamic>?> _tryDigLookup(String ip) async {
    try {
      final result = await Process.run('dig', [
        '-x',
        ip,
        '+short',
      ]).timeout(const Duration(seconds: 3));

      if (result.exitCode == 0) {
        final output = result.stdout.toString().trim();

        if (output.isNotEmpty && output != ip) {
          // 移除末尾的点
          final hostname = output.endsWith('.')
              ? output.substring(0, output.length - 1)
              : output;

          final domain = _extractDomain(hostname);
          final deviceType = _identifyDeviceType(hostname);
          final isLocal = _isLocalDomain(hostname);

          return {
            'hostname': hostname,
            'domain': domain,
            'deviceType': deviceType,
            'isLocal': isLocal,
          };
        }
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 解析nslookup输出
  String? _parseNslookupOutput(String output) {
    try {
      final lines = output.split('\n');

      for (final line in lines) {
        // 查找包含主机名的行
        if (line.contains('name =')) {
          final parts = line.split('name =');
          if (parts.length > 1) {
            final hostname = parts[1].trim();
            // 移除末尾的点
            return hostname.endsWith('.')
                ? hostname.substring(0, hostname.length - 1)
                : hostname;
          }
        }

        // 其他格式的主机名
        if (line.contains('=') && !line.contains('Address')) {
          final parts = line.split('=');
          if (parts.length > 1) {
            final hostname = parts[1].trim();
            if (hostname.contains('.') && !hostname.contains('in-addr.arpa')) {
              return hostname.endsWith('.')
                  ? hostname.substring(0, hostname.length - 1)
                  : hostname;
            }
          }
        }
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 提取域名
  String _extractDomain(String hostname) {
    try {
      final parts = hostname.split('.');
      if (parts.length >= 2) {
        // 返回最后两个部分作为域名
        return parts.sublist(parts.length - 2).join('.');
      }
      return hostname;
    } catch (e) {
      return hostname;
    }
  }

  /// 识别设备类型
  String _identifyDeviceType(String hostname) {
    final hostnameLower = hostname.toLowerCase();

    // 路由器和网关
    if (hostnameLower.contains('router') ||
        hostnameLower.contains('gateway') ||
        hostnameLower.contains('gw') ||
        hostnameLower.contains('modem')) {
      return 'Router/Gateway';
    }

    // Apple设备
    if (hostnameLower.contains('iphone') ||
        hostnameLower.contains('ipad') ||
        hostnameLower.contains('macbook') ||
        hostnameLower.contains('imac') ||
        hostnameLower.contains('mac-') ||
        hostnameLower.contains('appletv')) {
      return 'Apple Device';
    }

    // Android设备
    if (hostnameLower.contains('android') ||
        hostnameLower.contains('samsung') ||
        hostnameLower.contains('xiaomi') ||
        hostnameLower.contains('huawei') ||
        hostnameLower.contains('oneplus')) {
      return 'Android Device';
    }

    // 电脑
    if (hostnameLower.contains('pc') ||
        hostnameLower.contains('desktop') ||
        hostnameLower.contains('laptop') ||
        hostnameLower.contains('computer') ||
        hostnameLower.contains('win') ||
        hostnameLower.contains('ubuntu') ||
        hostnameLower.contains('linux')) {
      return 'Computer';
    }

    // 打印机
    if (hostnameLower.contains('printer') ||
        hostnameLower.contains('print') ||
        hostnameLower.contains('hp-') ||
        hostnameLower.contains('canon') ||
        hostnameLower.contains('epson')) {
      return 'Printer';
    }

    // NAS和存储设备
    if (hostnameLower.contains('nas') ||
        hostnameLower.contains('storage') ||
        hostnameLower.contains('synology') ||
        hostnameLower.contains('qnap') ||
        hostnameLower.contains('drobo')) {
      return 'NAS/Storage';
    }

    // 智能电视
    if (hostnameLower.contains('tv') ||
        hostnameLower.contains('smart') ||
        hostnameLower.contains('roku') ||
        hostnameLower.contains('chromecast') ||
        hostnameLower.contains('firetv')) {
      return 'Smart TV';
    }

    // 摄像头
    if (hostnameLower.contains('camera') ||
        hostnameLower.contains('cam') ||
        hostnameLower.contains('webcam') ||
        hostnameLower.contains('ipcam')) {
      return 'IP Camera';
    }

    // 游戏机
    if (hostnameLower.contains('xbox') ||
        hostnameLower.contains('playstation') ||
        hostnameLower.contains('ps4') ||
        hostnameLower.contains('ps5') ||
        hostnameLower.contains('nintendo') ||
        hostnameLower.contains('switch')) {
      return 'Game Console';
    }

    return 'Unknown Device';
  }

  /// 判断是否为本地域名
  bool _isLocalDomain(String hostname) {
    final localDomains = [
      '.local',
      '.lan',
      '.home',
      '.internal',
      '.private',
      '.localdomain',
    ];

    final hostnameLower = hostname.toLowerCase();
    return localDomains.any((domain) => hostnameLower.endsWith(domain));
  }

  /// 批量扫描
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

    final results = <ScanResult>[];
    final semaphore = Semaphore(config.maxConcurrency);

    final futures = ips.asMap().entries.map((entry) async {
      final index = entry.key;
      final ip = entry.value;

      await semaphore.acquire();
      try {
        onProgress?.call(ip, index / ips.length);

        final result = await scanSingle(ip, networkSegment);
        if (result != null) {
          results.add(result);
          onResult?.call(result);
        }
      } finally {
        semaphore.release();
      }
    });

    await Future.wait(futures);
    return results;
  }
}
