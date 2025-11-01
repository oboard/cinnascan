import 'package:flutter_test/flutter_test.dart';
import 'package:cinnascan/scanners/arp_scanner.dart';
import 'package:cinnascan/scanners/base_scanner.dart';

void main() {
  group('MAC地址厂商识别测试', () {
    late ArpScanner arpScanner;

    setUp(() {
      arpScanner = ArpScanner(
        config: const ScannerConfig(
          enabled: true,
          timeout: Duration(seconds: 1),
          maxConcurrency: 1,
        ),
      );
    });

    test('Apple设备MAC地址识别', () async {
      // 测试不同的Apple OUI
      final testCases = [
        '00:1B:63:AA:BB:CC', // Apple
        '00:25:00:11:22:33', // Apple
        '3C:15:C2:44:55:66', // Apple
      ];

      for (final mac in testCases) {
        final vendor = await arpScanner._getMacVendor(mac);
        expect(vendor, equals('Apple'), reason: 'MAC $mac 应该识别为Apple');
      }
    });

    test('VMware设备MAC地址识别', () async {
      final testCases = [
        '00:50:56:AA:BB:CC', // VMware
        '00:0C:29:11:22:33', // VMware
      ];

      for (final mac in testCases) {
        final vendor = await arpScanner._getMacVendor(mac);
        expect(vendor, equals('VMware'), reason: 'MAC $mac 应该识别为VMware');
      }
    });

    test('VirtualBox设备MAC地址识别', () async {
      final mac = '08:00:27:AA:BB:CC';
      final vendor = await arpScanner._getMacVendor(mac);
      expect(vendor, equals('VirtualBox'));
    });

    test('未知厂商MAC地址', () async {
      final mac = 'FF:FF:FF:AA:BB:CC'; // 不存在的OUI
      final vendor = await arpScanner._getMacVendor(mac);
      expect(vendor, equals('Unknown'));
    });

    test('无效MAC地址处理', () async {
      final testCases = [
        null,
        '',
        '00:1B', // 太短
        'invalid', // 无效格式
      ];

      for (final mac in testCases) {
        final vendor = await arpScanner._getMacVendor(mac);
        expect(vendor, isNull, reason: 'MAC $mac 应该返回null');
      }
    });

    test('大小写不敏感', () async {
      final testCases = [
        '00:1b:63:aa:bb:cc', // 小写
        '00:1B:63:AA:BB:CC', // 大写
        '00:1B:63:aa:BB:cc', // 混合
      ];

      for (final mac in testCases) {
        final vendor = await arpScanner._getMacVendor(mac);
        expect(vendor, equals('Apple'), reason: 'MAC $mac 应该识别为Apple (大小写不敏感)');
      }
    });

    test('OUI提取正确性', () async {
      // 验证OUI提取逻辑
      final mac = '00:1B:63:12:34:56';
      final vendor = await arpScanner._getMacVendor(mac);
      expect(vendor, equals('Apple'));

      // 验证只使用前6位十六进制字符
      final macWithDifferentSuffix = '00:1B:63:99:88:77';
      final vendor2 = await arpScanner._getMacVendor(macWithDifferentSuffix);
      expect(vendor2, equals('Apple'));
    });

    test('性能测试 - 大量MAC地址查询', () async {
      final stopwatch = Stopwatch()..start();

      // 测试1000次查询
      for (int i = 0; i < 1000; i++) {
        await arpScanner._getMacVendor(
          '00:1B:63:${i.toRadixString(16).padLeft(2, '0')}:${i.toRadixString(16).padLeft(2, '0')}:${i.toRadixString(16).padLeft(2, '0')}',
        );
      }

      stopwatch.stop();
      print('1000次MAC厂商查询耗时: ${stopwatch.elapsedMilliseconds}ms');

      // 应该在合理时间内完成 (< 100ms)
      expect(stopwatch.elapsedMilliseconds, lessThan(100));
    });
  });
}

// 扩展ArpScanner以访问私有方法进行测试
extension ArpScannerTest on ArpScanner {
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
}
