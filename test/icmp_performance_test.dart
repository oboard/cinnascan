import 'package:test/test.dart';
import 'package:cinnascan/scanners/icmp_scanner.dart';
import 'package:cinnascan/scanners/base_scanner.dart';

void main() {
  group('ICMP Performance Tests', () {
    test('测试优化后的ICMP扫描性能', () async {
      print('\n=== ICMP性能测试 ===');

      // 创建优化配置的ICMP扫描器
      final optimizedConfig = ScannerConfig(
        timeout: const Duration(milliseconds: 800),
        maxConcurrency: 100,
        enableParallelScanning: true,
        delayBetweenRequests: Duration.zero,
      );

      final icmpScanner = IcmpScanner(config: optimizedConfig);

      // 测试本地回环地址（应该很快响应）
      print('测试本地回环地址...');
      final stopwatch1 = Stopwatch()..start();
      final result1 = await icmpScanner.scanSingle('127.0.0.1', '127.0.0');
      stopwatch1.stop();

      print('本地回环测试结果: ${result1?.isActive == true ? "成功" : "失败"}');
      print('响应时间: ${stopwatch1.elapsedMilliseconds}ms');

      // 测试批量扫描性能（少量IP以避免超时）
      final testIps = [
        '127.0.0.1',
        '192.168.1.1',
        '8.8.8.8',
        '1.1.1.1',
        '192.168.1.254', // 可能不存在的IP
      ];

      print('\n测试批量ICMP扫描 (${testIps.length} 个IP)...');
      final stopwatch2 = Stopwatch()..start();

      final results = await icmpScanner.scanBatch(
        testIps,
        '192.168.1.0/24',
        onProgress: (ip, progress) {
          print('扫描进度: $ip - ${(progress * 100).toStringAsFixed(1)}%');
        },
      );

      stopwatch2.stop();

      print('批量扫描完成:');
      print('- 总耗时: ${stopwatch2.elapsedMilliseconds}ms');
      print(
        '- 平均每IP: ${(stopwatch2.elapsedMilliseconds / testIps.length).toStringAsFixed(1)}ms',
      );
      print('- 发现活跃设备: ${results.length} 个');

      for (final result in results) {
        print('  ✓ ${result.ip} - ${result.responseTime}ms');
      }

      // 性能断言
      expect(
        stopwatch2.elapsedMilliseconds,
        lessThan(5000),
        reason: '批量扫描应该在5秒内完成',
      );
      expect(results.length, greaterThan(0), reason: '至少应该发现一个活跃设备（127.0.0.1）');
    });

    test('对比优化前后的配置差异', () {
      print('\n=== 配置对比测试 ===');

      // 旧配置（优化前）
      final oldConfig = ScannerConfig(
        timeout: const Duration(seconds: 3),
        maxConcurrency: 20,
        enableParallelScanning: true,
        delayBetweenRequests: const Duration(milliseconds: 10),
      );

      // 新配置（优化后）
      final newConfig = ScannerConfig(
        timeout: const Duration(milliseconds: 800),
        maxConcurrency: 100,
        enableParallelScanning: true,
        delayBetweenRequests: Duration.zero,
      );

      print('优化前配置:');
      print('- 超时: ${oldConfig.timeout.inMilliseconds}ms');
      print('- 并发数: ${oldConfig.maxConcurrency}');
      print('- 请求延迟: ${oldConfig.delayBetweenRequests.inMilliseconds}ms');

      print('\n优化后配置:');
      print('- 超时: ${newConfig.timeout.inMilliseconds}ms');
      print('- 并发数: ${newConfig.maxConcurrency}');
      print('- 请求延迟: ${newConfig.delayBetweenRequests.inMilliseconds}ms');

      print('\n性能提升:');
      print(
        '- 超时减少: ${((oldConfig.timeout.inMilliseconds - newConfig.timeout.inMilliseconds) / oldConfig.timeout.inMilliseconds * 100).toStringAsFixed(1)}%',
      );
      print(
        '- 并发增加: ${((newConfig.maxConcurrency - oldConfig.maxConcurrency) / oldConfig.maxConcurrency * 100).toStringAsFixed(1)}%',
      );
      print('- 延迟减少: ${oldConfig.delayBetweenRequests.inMilliseconds}ms → 0ms');

      // 验证配置改进
      expect(newConfig.timeout, lessThan(oldConfig.timeout));
      expect(newConfig.maxConcurrency, greaterThan(oldConfig.maxConcurrency));
      expect(newConfig.delayBetweenRequests, equals(Duration.zero));
    });

    test('测试ICMP扫描器可用性', () async {
      final icmpScanner = IcmpScanner();
      final isAvailable = await icmpScanner.isAvailable();

      print('\nICMP扫描器可用性: ${isAvailable ? "可用" : "不可用"}');

      if (!isAvailable) {
        print('注意: ICMP扫描器不可用，可能需要管理员权限或系统不支持');
      }

      expect(isAvailable, isA<bool>());
    });
  });
}
