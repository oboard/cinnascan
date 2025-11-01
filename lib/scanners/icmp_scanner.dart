import 'dart:io';
import 'dart:async';
import 'package:super_ip/icmp.dart';
import 'package:super_raw/raw.dart';
import 'base_scanner.dart';

/// ICMP Ping扫描器
class IcmpScanner extends BaseScanner {
  IcmpScanner({ScannerConfig? config})
    : super(
        name: 'ICMP Ping扫描器',
        scanType: ScanResultType.icmpPing,
        config: config ?? const ScannerConfig(),
      );

  @override
  String get description => '使用ICMP Echo Request检测设备是否在线，这是最传统的ping方法';

  @override
  int get priority => 1; // 高优先级

  @override
  Future<bool> isAvailable() async {
    try {
      // 尝试创建原始套接字来检查权限
      final socket = await RawSocket.connect(InternetAddress('127.0.0.1'), 1);
      socket.close();
      return true;
    } catch (e) {
      // 如果没有权限创建原始套接字，回退到系统ping命令
      try {
        final result = await Process.run('ping', [
          '-c',
          '1',
          '127.0.0.1',
        ]).timeout(const Duration(seconds: 2));
        return result.exitCode == 0;
      } catch (e) {
        return false;
      }
    }
  }

  @override
  Future<ScanResult?> scanSingle(
    String ip,
    String networkSegment, {
    ScanProgressCallback? onProgress,
  }) async {
    try {
      // 首先尝试原始ICMP
      final rawResult = await _rawIcmpPing(ip, networkSegment);
      if (rawResult != null) {
        return rawResult;
      }

      // 如果原始ICMP失败，尝试系统ping命令
      return await _systemPing(ip, networkSegment);
    } catch (e) {
      return null;
    }
  }

  /// 使用原始套接字进行ICMP ping
  Future<ScanResult?> _rawIcmpPing(String ip, String networkSegment) async {
    try {
      final stopwatch = Stopwatch()..start();
      final targetIp = InternetAddress(ip);

      // 创建原始套接字进行ICMP ping
      final socket = await RawSocket.connect(targetIp, 1);

      // 创建ICMP包
      final icmpPacket = IcmpPacket()
        ..type = IcmpPacket.typeEchoRequest
        ..code = 0
        ..restOfHeader = 0x01000001
        ..payload = RawData(List.generate(32, (i) => i % 256));

      // 发送ICMP包
      final writer = RawWriter.withCapacity(icmpPacket.encodeSelfCapacity());
      icmpPacket.encodeSelf(writer);
      socket.write(writer.toUint8ListView());

      // 等待响应
      final completer = Completer<ScanResult?>();
      late StreamSubscription subscription;

      subscription = socket.listen((RawSocketEvent event) {
        if (event == RawSocketEvent.read) {
          final datagram = socket.read()?.toList();
          if (datagram != null) {
            try {
              final reader = RawReader.withBytes(datagram);
              final reply = IcmpPacket()..decodeSelf(reader);
              if (reply.type == IcmpPacket.typeEchoReply) {
                stopwatch.stop();
                subscription.cancel();
                socket.close();
                completer.complete(
                  ScanResult(
                    ip: ip,
                    isActive: true,
                    responseTime: stopwatch.elapsedMilliseconds,
                    networkSegment: networkSegment,
                    detectionMethod: ScanResultType.icmpPing,
                    additionalInfo: {'method': 'raw_icmp', 'pingable': true},
                  ),
                );
              }
            } catch (e) {
              // 忽略解析错误
            }
          }
        }
      });

      // 设置超时
      Timer(config.timeout, () {
        if (!completer.isCompleted) {
          subscription.cancel();
          socket.close();
          completer.complete(null);
        }
      });

      return await completer.future;
    } catch (e) {
      return null;
    }
  }

  /// 使用系统ping命令
  Future<ScanResult?> _systemPing(String ip, String networkSegment) async {
    try {
      final stopwatch = Stopwatch()..start();

      // 在macOS上使用ping命令，优化参数以提高速度
      final result = await Process.run('ping', [
        '-c', '1', // 只发送1个包
        '-W', '500', // 等待响应超时500ms（macOS参数）
        '-t', '1', // TTL设为1秒
        '-i', '0.1', // 包间隔0.1秒（对单包无效，但保持一致性）
        ip,
      ]).timeout(Duration(milliseconds: 800)); // 总超时800ms，比ping超时稍长

      stopwatch.stop();

      if (result.exitCode == 0) {
        // 尝试从ping输出中提取响应时间
        int responseTime = stopwatch.elapsedMilliseconds;
        final output = result.stdout.toString();
        final timeMatch = RegExp(r'time=(\d+\.?\d*)\s*ms').firstMatch(output);
        if (timeMatch != null) {
          responseTime = double.parse(timeMatch.group(1)!).round();
        }

        return ScanResult(
          ip: ip,
          isActive: true,
          responseTime: responseTime,
          networkSegment: networkSegment,
          detectionMethod: ScanResultType.icmpPing,
          additionalInfo: {
            'method': 'system_ping',
            'pingable': true,
            'ping_output': output.trim(),
          },
        );
      }

      return null;
    } catch (e) {
      return null;
    }
  }
}
