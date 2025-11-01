// 扫描器模块单元测试
// 测试所有扫描器的基本功能和接口实现

import 'package:cinnascan/scanners/base_scanner.dart';
import 'package:cinnascan/scanners/icmp_scanner.dart';
import 'package:cinnascan/scanners/tcp_scanner.dart';
import 'package:cinnascan/scanners/arp_scanner.dart';
import 'package:cinnascan/scanners/mdns_scanner.dart';
import 'package:cinnascan/scanners/upnp_scanner.dart';
import 'package:cinnascan/scanners/dns_scanner.dart';
import 'package:cinnascan/scanners/ipv6_scanner.dart';
import 'package:cinnascan/scanners/scan_manager.dart';
import 'package:test/test.dart';

void main() {
  group('扫描器基础测试', () {
    test('ICMP扫描器初始化测试', () {
      final scanner = IcmpScanner();
      expect(scanner, isA<IcmpScanner>());
      expect(scanner, isA<BaseScanner>());
      expect(scanner.name, equals('ICMP Ping扫描器'));
      expect(scanner.scanType, equals(ScanResultType.icmpPing));
      expect(scanner.priority, greaterThan(0));
    });

    test('TCP扫描器初始化测试', () {
      final scanner = TcpScanner();
      expect(scanner, isA<TcpScanner>());
      expect(scanner, isA<BaseScanner>());
      expect(scanner.name, equals('TCP端口扫描器'));
      expect(scanner.scanType, equals(ScanResultType.tcpPort));
      expect(scanner.priority, greaterThan(0));
    });

    test('ARP扫描器初始化测试', () {
      final scanner = ArpScanner();
      expect(scanner, isA<ArpScanner>());
      expect(scanner, isA<BaseScanner>());
      expect(scanner.name, equals('ARP表扫描器'));
      expect(scanner.scanType, equals(ScanResultType.arpTable));
      expect(scanner.priority, greaterThan(0));
    });

    test('mDNS扫描器初始化测试', () {
      final scanner = MdnsScanner();
      expect(scanner, isA<MdnsScanner>());
      expect(scanner, isA<BaseScanner>());
      expect(scanner.name, equals('Bonjour/mDNS扫描器'));
      expect(scanner.scanType, equals(ScanResultType.bonjour));
      expect(scanner.priority, greaterThan(0));
    });

    test('UPnP扫描器初始化测试', () {
      final scanner = UpnpScanner();
      expect(scanner, isA<UpnpScanner>());
      expect(scanner, isA<BaseScanner>());
      expect(scanner.name, equals('UPnP SSDP扫描器'));
      expect(scanner.scanType, equals(ScanResultType.upnp));
      expect(scanner.priority, greaterThan(0));
    });

    test('DNS扫描器初始化测试', () {
      final scanner = DnsScanner();
      expect(scanner, isA<DnsScanner>());
      expect(scanner, isA<BaseScanner>());
      expect(scanner.name, equals('DNS反向解析扫描器'));
      expect(scanner.scanType, equals(ScanResultType.dnsReverse));
      expect(scanner.priority, greaterThan(0));
    });

    test('IPv6扫描器初始化测试', () {
      final scanner = Ipv6Scanner();
      expect(scanner, isA<Ipv6Scanner>());
      expect(scanner, isA<BaseScanner>());
      expect(scanner.name, equals('IPv6探测扫描器'));
      expect(scanner.scanType, equals(ScanResultType.ipv6));
      expect(scanner.priority, greaterThan(0));
    });
  });

  group('扫描管理器测试', () {
    test('扫描管理器初始化测试', () {
      final manager = ScanManager();
      expect(manager, isA<ScanManager>());
      expect(manager.availableScanners.length, equals(7));
      expect(manager.enabledScanners.length, equals(7));
    });

    test('扫描器启用/禁用测试', () {
      final manager = ScanManager();

      // 测试禁用扫描器
      manager.setScannerEnabled(ScanResultType.icmpPing, false);
      expect(manager.isScannerEnabled(ScanResultType.icmpPing), isFalse);
      expect(manager.enabledScanners.length, equals(6));

      // 测试重新启用扫描器
      manager.setScannerEnabled(ScanResultType.icmpPing, true);
      expect(manager.isScannerEnabled(ScanResultType.icmpPing), isTrue);
      expect(manager.enabledScanners.length, equals(7));
    });

    test('预设配置测试', () {
      final manager = ScanManager();

      // 测试快速扫描配置
      final quickConfig = manager.getQuickScanConfig();
      expect(quickConfig[ScanResultType.icmpPing], isTrue);
      expect(quickConfig[ScanResultType.tcpPort], isTrue);
      expect(quickConfig[ScanResultType.arpTable], isFalse);

      // 测试完整扫描配置
      final fullConfig = manager.getFullScanConfig();
      expect(fullConfig.values.every((enabled) => enabled), isTrue);

      // 测试推荐配置
      final recommendedConfig = manager.getRecommendedConfig();
      expect(recommendedConfig[ScanResultType.icmpPing], isTrue);
      expect(recommendedConfig[ScanResultType.dnsReverse], isTrue);
    });
  });

  group('扫描结果测试', () {
    test('ScanResult创建测试', () {
      final result = ScanResult(
        ip: '192.168.1.1',
        isActive: true,
        detectionMethod: ScanResultType.icmpPing,
        responseTime: 10,
        networkSegment: '192.168.1',
        hostname: 'router.local',
        additionalInfo: {'deviceType': 'router'},
      );

      expect(result.ip, equals('192.168.1.1'));
      expect(result.isActive, isTrue);
      expect(result.detectionMethod, equals(ScanResultType.icmpPing));
      expect(result.responseTime, equals(10));
      expect(result.hostname, equals('router.local'));
      expect(result.detectionMethodName, equals('ICMP Ping'));
    });

    test('ScanResultType枚举测试', () {
      expect(ScanResultType.values.length, equals(9));
      expect(ScanResultType.values.contains(ScanResultType.icmpPing), isTrue);
      expect(ScanResultType.values.contains(ScanResultType.tcpPort), isTrue);
      expect(ScanResultType.values.contains(ScanResultType.arpTable), isTrue);
      expect(ScanResultType.values.contains(ScanResultType.bonjour), isTrue);
      expect(ScanResultType.values.contains(ScanResultType.upnp), isTrue);
      expect(ScanResultType.values.contains(ScanResultType.dnsReverse), isTrue);
      expect(ScanResultType.values.contains(ScanResultType.ipv6), isTrue);
    });
  });

  group('扫描器可用性测试', () {
    test('ICMP扫描器可用性检查', () async {
      final scanner = IcmpScanner();
      final isAvailable = await scanner.isAvailable();
      expect(isAvailable, isA<bool>());
    });

    test('TCP扫描器可用性检查', () async {
      final scanner = TcpScanner();
      final isAvailable = await scanner.isAvailable();
      expect(isAvailable, isA<bool>());
    });

    test('ARP扫描器可用性检查', () async {
      final scanner = ArpScanner();
      final isAvailable = await scanner.isAvailable();
      expect(isAvailable, isA<bool>());
    });

    test('DNS扫描器可用性检查', () async {
      final scanner = DnsScanner();
      final isAvailable = await scanner.isAvailable();
      expect(isAvailable, isA<bool>());
    });
  });

  group('扫描器配置测试', () {
    test('ScannerConfig默认值测试', () {
      const config = ScannerConfig();
      expect(config.timeout, equals(const Duration(seconds: 3)));
      expect(config.maxConcurrency, equals(10));
      expect(config.enabled, isTrue);
      expect(config.customParams, isEmpty);
    });

    test('ScannerConfig自定义值测试', () {
      const config = ScannerConfig(
        timeout: Duration(seconds: 5),
        maxConcurrency: 20,
        enabled: false,
        customParams: {'test': 'value'},
      );
      expect(config.timeout, equals(const Duration(seconds: 5)));
      expect(config.maxConcurrency, equals(20));
      expect(config.enabled, isFalse);
      expect(config.customParams['test'], equals('value'));
    });
  });

  group('本地回环测试', () {
    test('本地回环地址扫描测试', () async {
      final scanner = TcpScanner();

      // 测试扫描本地回环地址（应该总是可达的）
      final result = await scanner.scanSingle('127.0.0.1', '127.0.0');

      // 本地回环地址应该有响应（至少某些端口是开放的）
      expect(result, isNotNull);
      if (result != null) {
        expect(result.ip, equals('127.0.0.1'));
        expect(result.isActive, isTrue);
        expect(result.detectionMethod, equals(ScanResultType.tcpPort));
      }
    }, timeout: const Timeout(Duration(seconds: 10)));

    test('DNS扫描器本地测试', () async {
      final scanner = DnsScanner();

      // 测试扫描本地回环地址
      final result = await scanner.scanSingle('127.0.0.1', '127.0.0');

      // DNS扫描可能返回结果也可能不返回，这取决于系统配置
      expect(result, anyOf(isNull, isA<ScanResult>()));
      if (result != null) {
        expect(result.ip, equals('127.0.0.1'));
        expect(result.detectionMethod, equals(ScanResultType.dnsReverse));
      }
    }, timeout: const Timeout(Duration(seconds: 10)));
  });

  group('批量扫描测试', () {
    test('空IP列表批量扫描测试', () async {
      final scanner = TcpScanner();
      final results = await scanner.scanBatch([], '192.168.1');
      expect(results, isEmpty);
    });

    test('单个IP批量扫描测试', () async {
      final scanner = TcpScanner();
      final results = await scanner.scanBatch(['127.0.0.1'], '127.0.0');
      expect(results, isA<List<ScanResult>>());
      // 结果可能为空或包含一个结果，取决于本地配置
      expect(results.length, lessThanOrEqualTo(1));
    }, timeout: const Timeout(Duration(seconds: 15)));
  });

  group('错误处理测试', () {
    test('无效IP地址扫描测试', () async {
      final scanner = TcpScanner();

      // 测试无效IP地址
      final result = await scanner.scanSingle('999.999.999.999', '999.999.999');
      expect(result, isNull);
    });

    test('扫描器错误处理测试', () async {
      final scanner = TcpScanner();

      // 测试扫描器对空字符串的处理
      final result = await scanner.scanSingle('', '');
      expect(result, isNull);
    });
  });
}
