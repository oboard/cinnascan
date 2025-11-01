import 'package:flutter_test/flutter_test.dart';
import 'package:cinnascan/scanners/scan_manager.dart';
import 'package:cinnascan/scanners/base_scanner.dart';

void main() {
  group('扫描性能测试', () {
    late ScanManager scanManager;

    setUp(() {
      scanManager = ScanManager();
    });

    test('测试智能扫描配置', () {
      // 测试速度优先配置
      final speedConfig = scanManager.getSmartScanConfig(prioritizeSpeed: true);
      expect(speedConfig[ScanResultType.icmpPing], true);
      expect(speedConfig[ScanResultType.tcpPort], true);
      expect(speedConfig[ScanResultType.arpTable], true);
      expect(speedConfig[ScanResultType.bonjour], false);
      expect(speedConfig[ScanResultType.upnp], false);

      // 测试全面扫描配置
      final comprehensiveConfig = scanManager.getSmartScanConfig(
        prioritizeSpeed: false,
        includeAdvanced: true,
      );
      expect(comprehensiveConfig[ScanResultType.icmpPing], true);
      expect(comprehensiveConfig[ScanResultType.bonjour], true);
      expect(comprehensiveConfig[ScanResultType.upnp], true);
    });

    test('测试性能监控功能', () {
      // 模拟扫描性能数据
      scanManager.recordScanPerformance(ScanResultType.icmpPing, 100, true);
      scanManager.recordScanPerformance(ScanResultType.icmpPing, 150, true);
      scanManager.recordScanPerformance(ScanResultType.icmpPing, 200, false);

      final recommendations = scanManager.getPerformanceRecommendations();
      expect(recommendations.containsKey('ScanResultType.icmpPing'), true);

      final icmpData = recommendations['ScanResultType.icmpPing'];
      expect(icmpData['sampleSize'], 3);
      expect(icmpData['avgResponseTime'], greaterThan(0));
      expect(icmpData['successRate'], greaterThan(0));
    });

    test('测试网络环境评估', () {
      // 添加一些性能数据
      for (int i = 0; i < 10; i++) {
        scanManager.recordScanPerformance(
          ScanResultType.icmpPing,
          100 + i * 10,
          true,
        );
        scanManager.recordScanPerformance(
          ScanResultType.tcpPort,
          200 + i * 20,
          i < 8,
        );
      }

      final assessment = scanManager.assessNetworkEnvironment();
      expect(assessment.containsKey('networkQuality'), true);
      expect(assessment.containsKey('avgResponseTime'), true);
      expect(assessment.containsKey('avgSuccessRate'), true);
      expect(assessment.containsKey('totalSamples'), true);

      print('网络环境评估结果: ${assessment['networkQuality']}');
      print('平均响应时间: ${assessment['avgResponseTime']}ms');
      print('平均成功率: ${assessment['avgSuccessRate']}%');
    });

    test('测试扫描器配置优化', () {
      final stats = scanManager.getNetworkStats();
      expect(stats.isNotEmpty, true);

      // 验证ICMP扫描器的极致优化配置
      final icmpStats = stats.values.firstWhere(
        (stat) => stat['maxConcurrency'] == 200,
        orElse: () => null,
      );
      expect(icmpStats, isNotNull);
      expect(icmpStats['timeout'], lessThanOrEqualTo(500));

      print('扫描器配置统计:');
      stats.forEach((scanType, config) {
        print(
          '$scanType: 并发=${config['maxConcurrency']}, 超时=${config['timeout']}ms',
        );
      });
    });

    test('测试启用的扫描器数量', () {
      final enabledScanners = scanManager.enabledScanners;
      expect(enabledScanners.length, greaterThan(0));

      // 验证默认启用的快速扫描器
      final enabledTypes = enabledScanners.map((s) => s.scanType).toSet();
      expect(enabledTypes.contains(ScanResultType.icmpPing), true);
      expect(enabledTypes.contains(ScanResultType.tcpPort), true);
      expect(enabledTypes.contains(ScanResultType.arpTable), true);

      print('默认启用的扫描器数量: ${enabledScanners.length}');
      for (final scanner in enabledScanners) {
        print('- ${scanner.name} (并发: ${scanner.config.maxConcurrency})');
      }
    });
  });
}
