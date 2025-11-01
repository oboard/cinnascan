import 'dart:io';
import 'dart:async';
import 'package:multicast_dns/multicast_dns.dart';
import 'base_scanner.dart';

/// Bonjour/mDNS扫描器
class MdnsScanner extends BaseScanner {
  MdnsScanner({ScannerConfig? config})
    : super(
        name: 'Bonjour/mDNS扫描器',
        scanType: ScanResultType.bonjour,
        config: config ?? const ScannerConfig(),
      );

  @override
  String get description => '通过Bonjour/mDNS协议发现Apple设备和本地服务';

  @override
  int get priority => 75;

  @override
  Future<bool> isAvailable() async {
    try {
      // 简单测试是否可以创建mDNS客户端
      final client = MDnsClient();
      await client.start();
      client.stop();
      return true;
    } catch (e) {
      print('mDNS不可用: $e');
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
      final client = MDnsClient();
      await client.start();

      try {
        // 查询常见的mDNS服务
        final services = [
          '_http._tcp.local',
          '_https._tcp.local',
          '_ssh._tcp.local',
          '_airplay._tcp.local',
          '_raop._tcp.local',
          '_device-info._tcp.local',
          '_apple-mobdev2._tcp.local',
        ];

        for (final service in services) {
          await for (final PtrResourceRecord ptr
              in client
                  .lookup<PtrResourceRecord>(
                    ResourceRecordQuery.serverPointer(service),
                  )
                  .timeout(const Duration(seconds: 2))) {
            // 获取SRV记录以获取端口和主机名
            await for (final SrvResourceRecord srv
                in client
                    .lookup<SrvResourceRecord>(
                      ResourceRecordQuery.service(ptr.domainName),
                    )
                    .timeout(const Duration(seconds: 1))) {
              // 检查是否是目标IP
              final targetHost = srv.target.toLowerCase();
              if (targetHost.contains(ip.replaceAll('.', '-')) ||
                  await _resolveHostToIp(srv.target) == ip) {
                return ScanResult(
                  ip: ip,
                  isActive: true,
                  responseTime: 0,
                  networkSegment: networkSegment,
                  detectionMethod: ScanResultType.bonjour,
                  hostname: srv.target,
                  additionalInfo: {
                    'service_name': ptr.domainName,
                    'service_type': service,
                    'port': srv.port.toString(),
                    'device_type': _getDeviceType(service, ptr.domainName),
                  },
                );
              }
            }
          }
        }

        return null;
      } finally {
        client.stop();
      }
    } catch (e) {
      return null;
    }
  }

  /// 解析主机名到IP地址
  Future<String?> _resolveHostToIp(String hostname) async {
    try {
      final addresses = await InternetAddress.lookup(hostname);
      if (addresses.isNotEmpty) {
        return addresses.first.address;
      }
    } catch (e) {
      // 解析失败
    }
    return null;
  }

  /// 根据服务类型判断设备类型
  String _getDeviceType(String serviceType, String serviceName) {
    if (serviceType.contains('airplay') || serviceType.contains('raop')) {
      return 'Apple TV/AirPlay Device';
    } else if (serviceType.contains('homekit') || serviceType.contains('hap')) {
      return 'HomeKit Device';
    } else if (serviceType.contains('apple-mobdev')) {
      return 'iOS Device';
    } else if (serviceType.contains('ssh')) {
      return 'SSH Server';
    } else if (serviceType.contains('http')) {
      return 'Web Server';
    } else {
      return 'mDNS Device';
    }
  }

  @override
  Future<List<ScanResult>> scanBatch(
    List<String> ips,
    String networkSegment, {
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  }) async {
    final results = <ScanResult>[];

    if (ips.isEmpty) return results;

    // 检查mDNS是否可用
    if (!await isAvailable()) {
      print('mDNS扫描器不可用，跳过mDNS扫描');
      return results;
    }

    try {
      final client = MDnsClient();
      await client.start();

      try {
        // 查询所有常见服务
        final services = [
          '_http._tcp.local',
          '_https._tcp.local',
          '_ssh._tcp.local',
          '_airplay._tcp.local',
          '_raop._tcp.local',
          '_device-info._tcp.local',
          '_apple-mobdev2._tcp.local',
          '_homekit._tcp.local',
          '_hap._tcp.local',
        ];

        final foundDevices = <String, ScanResult>{};

        // 并行查询所有服务以提高效率
        final serviceFutures = services
            .map(
              (service) => _queryService(
                client,
                service,
                ips,
                networkSegment,
                foundDevices,
                onResult,
              ),
            )
            .toList();

        // 等待所有服务查询完成
        await Future.wait(serviceFutures);

        results.addAll(foundDevices.values);
        onProgress?.call('', 1.0);
      } finally {
        client.stop();
      }
    } catch (e) {
      // mDNS查询失败
      print('mDNS批量扫描失败: $e');
    }

    return results;
  }

  /// 查询单个服务类型
  Future<void> _queryService(
    MDnsClient client,
    String service,
    List<String> targetIps,
    String networkSegment,
    Map<String, ScanResult> foundDevices,
    ScanResultCallback? onResult,
  ) async {
    try {
      await for (final PtrResourceRecord ptr
          in client
              .lookup<PtrResourceRecord>(
                ResourceRecordQuery.serverPointer(service),
              )
              .timeout(const Duration(seconds: 2))) {
        await for (final SrvResourceRecord srv
            in client
                .lookup<SrvResourceRecord>(
                  ResourceRecordQuery.service(ptr.domainName),
                )
                .timeout(const Duration(seconds: 1))) {
          // 尝试解析主机名到IP
          final resolvedIp = await _resolveHostToIp(srv.target);
          if (resolvedIp != null && targetIps.contains(resolvedIp)) {
            final result = ScanResult(
              ip: resolvedIp,
              isActive: true,
              responseTime: 0,
              networkSegment: networkSegment,
              detectionMethod: ScanResultType.bonjour,
              hostname: srv.target,
              additionalInfo: {
                'service_name': ptr.domainName,
                'service_type': service,
                'port': srv.port.toString(),
                'device_type': _getDeviceType(service, ptr.domainName),
              },
            );

            foundDevices[resolvedIp] = result;
            onResult?.call(result);
          }
        }
      }
    } catch (e) {
      // 服务查询失败，继续其他服务
      print('mDNS服务查询失败 $service: $e');
    }
  }
}
