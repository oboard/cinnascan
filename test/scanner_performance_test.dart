import 'package:test/test.dart';
import 'package:cinnascan/scanners/scan_manager.dart';
import 'package:cinnascan/scanners/base_scanner.dart';

void main() {
  group('Scanner Performance Tests', () {
    late ScanManager scanManager;

    setUp(() {
      scanManager = ScanManager();
    });

    tearDown(() {
      scanManager.dispose();
    });

    test('测试扫描器配置优化', () async {
      // 测试高性能配置
      final highPerfConfig = ScannerConfig(
        timeout: const Duration(seconds: 1),
        maxConcurrency: 100,
        enableParallelScanning: true,
        delayBetweenRequests: const Duration(milliseconds: 5),
      );

      // 测试保守配置
      final conservativeConfig = ScannerConfig(
        timeout: const Duration(seconds: 5),
        maxConcurrency: 10,
        enableParallelScanning: false,
        delayBetweenRequests: const Duration(milliseconds: 100),
      );

      print('\n=== 配置测试 ===');
      print(
        '高性能配置: 超时${highPerfConfig.timeout.inSeconds}s, 并发${highPerfConfig.maxConcurrency}, 延迟${highPerfConfig.delayBetweenRequests.inMilliseconds}ms',
      );
      print(
        '保守配置: 超时${conservativeConfig.timeout.inSeconds}s, 并发${conservativeConfig.maxConcurrency}, 延迟${conservativeConfig.delayBetweenRequests.inMilliseconds}ms',
      );

      expect(highPerfConfig.enableParallelScanning, isTrue);
      expect(conservativeConfig.enableParallelScanning, isFalse);
      expect(
        highPerfConfig.maxConcurrency,
        greaterThan(conservativeConfig.maxConcurrency),
      );
    });

    test('测试并发控制', () async {
      // 测试信号量控制
      final semaphore = Semaphore(2); // 最大2个并发
      final futures = <Future<void>>[];

      for (int i = 0; i < 5; i++) {
        futures.add(
          semaphore.acquire().then((_) async {
            print('任务 $i 开始执行');
            await Future.delayed(Duration(milliseconds: 100));
            print('任务 $i 完成');
            semaphore.release();
          }),
        );
      }

      final stopwatch = Stopwatch()..start();
      await Future.wait(futures);
      stopwatch.stop();

      print('并发控制测试完成，耗时: ${stopwatch.elapsedMilliseconds}ms');

      // 5个任务，每个100ms，最大并发2，应该需要约300ms
      expect(stopwatch.elapsedMilliseconds, greaterThan(250));
      expect(stopwatch.elapsedMilliseconds, lessThan(400));
    });

    test('测试异步扫描基本功能', () async {
      // 只测试少量IP以避免超时
      final testIps = ['127.0.0.1', '192.168.1.1'];

      print('开始测试异步扫描基本功能...');
      print('测试IP数量: ${testIps.length}');

      // 测试并行扫描
      final stopwatch = Stopwatch()..start();
      final results = await scanManager.scanBatch(
        testIps,
        '192.168.1.0/24',
        parallelScanners: true,
        onProgress: (ip, progress) {
          print('扫描进度: ${(progress * 100).toStringAsFixed(1)}%');
        },
      );
      stopwatch.stop();

      print('扫描完成，耗时: ${stopwatch.elapsedMilliseconds}ms');
      print('扫描结果数: ${results.length}');

      // 验证结果
      expect(results, isNotNull);
      expect(stopwatch.elapsedMilliseconds, lessThan(10000)); // 应该在10秒内完成
    }, timeout: Timeout(Duration(seconds: 15)));

    test('测试Turbo扫描功能', () async {
      final testIps = ['127.0.0.1'];

      print('开始测试Turbo扫描...');

      final stopwatch = Stopwatch()..start();
      final results = await scanManager.turboScan(
        testIps,
        '127.0.0.0/24',
        onProgress: (ip, progress) {
          print('Turbo扫描进度: ${(progress * 100).toStringAsFixed(1)}%');
        },
      );
      stopwatch.stop();

      print('Turbo扫描完成，耗时: ${stopwatch.elapsedMilliseconds}ms');
      print('Turbo扫描结果数: ${results.length}');

      expect(results, isNotNull);
      expect(stopwatch.elapsedMilliseconds, lessThan(8000)); // 应该在8秒内完成
    }, timeout: Timeout(Duration(seconds: 10)));
  });
}
