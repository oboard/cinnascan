import 'dart:io';
import 'dart:async';
import 'base_scanner.dart';

/// IPv6探测扫描器
class Ipv6Scanner extends BaseScanner {
  Ipv6Scanner({ScannerConfig? config})
    : super(
        name: 'IPv6探测扫描器',
        scanType: ScanResultType.ipv6,
        config: config ?? const ScannerConfig(),
      );

  @override
  String get description => '检测设备的IPv6地址和IPv6服务支持';

  @override
  int get priority => 2; // 较低优先级

  @override
  Future<bool> isAvailable() async {
    try {
      // 检查系统是否支持IPv6
      final interfaces = await NetworkInterface.list();
      for (final interface in interfaces) {
        for (final addr in interface.addresses) {
          if (addr.type == InternetAddressType.IPv6 && !addr.isLoopback) {
            return true;
          }
        }
      }
      return false;
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

      // 探测IPv6地址
      final ipv6Info = await _probeIpv6(ip);

      stopwatch.stop();

      if (ipv6Info != null) {
        return ScanResult(
          ip: ip,
          isActive: true,
          responseTime: stopwatch.elapsedMilliseconds,
          networkSegment: networkSegment,
          detectionMethod: ScanResultType.ipv6,
          hostname: ipv6Info['hostname'],
          additionalInfo: {
            'ipv6_available': true,
            'ipv6_addresses': ipv6Info['addresses'],
            'ipv6_services': ipv6Info['services'],
            'link_local': ipv6Info['linkLocal'],
            'global_unicast': ipv6Info['globalUnicast'],
          },
        );
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 探测IPv6
  Future<Map<String, dynamic>?> _probeIpv6(String ipv4) async {
    try {
      final ipv6Addresses = <String>[];
      final services = <String>[];
      String? hostname;
      bool hasLinkLocal = false;
      bool hasGlobalUnicast = false;

      // 方法1: 通过邻居发现协议(NDP)
      final ndpAddresses = await _discoverViaNeighborDiscovery(ipv4);
      ipv6Addresses.addAll(ndpAddresses);

      // 方法2: 通过DNS AAAA记录查询
      final dnsAddresses = await _queryAAAARecord(ipv4);
      ipv6Addresses.addAll(dnsAddresses);

      // 方法3: 通过常见IPv6地址模式推测
      final predictedAddresses = await _predictIpv6Addresses(ipv4);
      ipv6Addresses.addAll(predictedAddresses);

      // 去重
      final uniqueAddresses = ipv6Addresses.toSet().toList();

      // 验证发现的IPv6地址
      final validAddresses = <String>[];
      for (final addr in uniqueAddresses) {
        if (await _verifyIpv6Address(addr)) {
          validAddresses.add(addr);

          // 分类IPv6地址
          if (addr.startsWith('fe80:')) {
            hasLinkLocal = true;
          } else if (!addr.startsWith('fc') && !addr.startsWith('fd')) {
            hasGlobalUnicast = true;
          }

          // 检查IPv6服务
          final ipv6Services = await _checkIpv6Services(addr);
          services.addAll(ipv6Services);
        }
      }

      // 尝试获取主机名
      if (validAddresses.isNotEmpty) {
        hostname = await _getIpv6Hostname(validAddresses.first);
      }

      if (validAddresses.isNotEmpty) {
        return {
          'addresses': validAddresses,
          'services': services.toSet().toList(),
          'hostname': hostname,
          'linkLocal': hasLinkLocal,
          'globalUnicast': hasGlobalUnicast,
        };
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 通过邻居发现协议发现IPv6地址
  Future<List<String>> _discoverViaNeighborDiscovery(String ipv4) async {
    try {
      // 在macOS上使用ndp命令
      final result = await Process.run('ndp', [
        '-a',
      ]).timeout(const Duration(seconds: 3));

      if (result.exitCode == 0) {
        final output = result.stdout.toString();
        final addresses = <String>[];

        final lines = output.split('\n');
        for (final line in lines) {
          // 解析ndp输出格式
          final parts = line.split(RegExp(r'\s+'));
          if (parts.length >= 2) {
            final ipv6 = parts[0];
            final mac = parts.length > 1 ? parts[1] : '';

            // 验证IPv6地址格式
            if (_isValidIpv6(ipv6) && mac.isNotEmpty) {
              addresses.add(ipv6);
            }
          }
        }

        return addresses;
      }

      return [];
    } catch (e) {
      return [];
    }
  }

  /// 查询AAAA记录
  Future<List<String>> _queryAAAARecord(String ipv4) async {
    try {
      // 首先尝试获取主机名
      String? hostname;
      try {
        final result = await InternetAddress(ipv4).reverse();
        hostname = result.host;
      } catch (e) {
        // 无法获取主机名
      }

      if (hostname != null && hostname != ipv4) {
        // 查询AAAA记录
        try {
          final addresses = await InternetAddress.lookup(
            hostname,
            type: InternetAddressType.IPv6,
          );
          return addresses.map((addr) => addr.address).toList();
        } catch (e) {
          // AAAA查询失败
        }
      }

      return [];
    } catch (e) {
      return [];
    }
  }

  /// 预测IPv6地址
  Future<List<String>> _predictIpv6Addresses(String ipv4) async {
    try {
      final addresses = <String>[];

      // 获取本地IPv6前缀
      final localPrefixes = await _getLocalIpv6Prefixes();

      // 从IPv4地址生成可能的IPv6地址
      final ipv4Parts = ipv4.split('.');
      if (ipv4Parts.length == 4) {
        final lastOctet = int.tryParse(ipv4Parts[3]);
        if (lastOctet != null) {
          for (final prefix in localPrefixes) {
            // EUI-64格式
            final eui64 = '${prefix}::${lastOctet.toRadixString(16)}';
            addresses.add(eui64);

            // 简单映射
            final simple = '${prefix}::${ipv4Parts[2]}.${ipv4Parts[3]}';
            addresses.add(simple);

            // 完整IPv4映射
            final mapped = '${prefix}::${ipv4Parts.join('.')}';
            addresses.add(mapped);
          }
        }
      }

      return addresses;
    } catch (e) {
      return [];
    }
  }

  /// 获取本地IPv6前缀
  Future<List<String>> _getLocalIpv6Prefixes() async {
    try {
      final prefixes = <String>[];
      final interfaces = await NetworkInterface.list();

      for (final interface in interfaces) {
        for (final addr in interface.addresses) {
          if (addr.type == InternetAddressType.IPv6 && !addr.isLoopback) {
            final address = addr.address;

            // 提取前缀 (前64位)
            if (address.contains('::')) {
              final parts = address.split('::');
              if (parts.isNotEmpty) {
                prefixes.add('${parts[0]}::');
              }
            } else {
              // 完整IPv6地址，取前4组
              final groups = address.split(':');
              if (groups.length >= 4) {
                prefixes.add('${groups.sublist(0, 4).join(':')}::');
              }
            }
          }
        }
      }

      return prefixes.toSet().toList();
    } catch (e) {
      return ['fe80::', '2001:db8::']; // 默认前缀
    }
  }

  /// 验证IPv6地址
  Future<bool> _verifyIpv6Address(String ipv6) async {
    try {
      // 首先验证格式
      if (!_isValidIpv6(ipv6)) {
        return false;
      }

      // 尝试ping IPv6地址
      final result = await Process.run('ping6', [
        '-c',
        '1',
        '-t',
        '1',
        ipv6,
      ]).timeout(const Duration(seconds: 2));

      return result.exitCode == 0;
    } catch (e) {
      return false;
    }
  }

  /// 检查IPv6服务
  Future<List<String>> _checkIpv6Services(String ipv6) async {
    final services = <String>[];

    // 常见IPv6服务端口
    final ports = [22, 80, 443, 5353, 8080];

    for (final port in ports) {
      try {
        final socket = await Socket.connect(
          ipv6,
          port,
          timeout: const Duration(milliseconds: 500),
        );
        socket.destroy();

        switch (port) {
          case 22:
            services.add('SSH');
            break;
          case 80:
            services.add('HTTP');
            break;
          case 443:
            services.add('HTTPS');
            break;
          case 5353:
            services.add('mDNS');
            break;
          case 8080:
            services.add('HTTP-Alt');
            break;
        }
      } catch (e) {
        // 端口不可达
      }
    }

    return services;
  }

  /// 获取IPv6主机名
  Future<String?> _getIpv6Hostname(String ipv6) async {
    try {
      final result = await InternetAddress(ipv6).reverse();
      return result.host != ipv6 ? result.host : null;
    } catch (e) {
      return null;
    }
  }

  /// 验证IPv6地址格式
  bool _isValidIpv6(String address) {
    try {
      // 基本格式检查
      if (address.isEmpty) return false;

      // IPv6地址应该包含冒号
      if (!address.contains(':')) return false;

      // 不能有超过7个冒号（除了::的情况）
      final colonCount = address.split('').where((c) => c == ':').length;
      if (colonCount > 7) return false;

      // 尝试创建InternetAddress对象验证
      final addr = InternetAddress(address);
      return addr.type == InternetAddressType.IPv6;
    } catch (e) {
      return false;
    }
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
