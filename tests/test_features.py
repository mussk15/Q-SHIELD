from qshield.monitor.features import PacketRecord, SlidingWindowFeatureExtractor


def test_feature_window_counts_packets_and_ports():
    extractor = SlidingWindowFeatureExtractor(window_seconds=10)
    extractor.add_packet(PacketRecord(100, "10.0.0.5", "10.0.0.1", 5000, 22, "S", 60))
    extractor.add_packet(PacketRecord(101, "10.0.0.5", "10.0.0.1", 5001, 23, "S", 60))
    rows = extractor.snapshot(now=102)
    assert len(rows) == 1
    row = rows[0]
    assert row.packet_count == 2
    assert row.syn_count == 2
    assert row.distinct_dst_ports == 2
    assert row.bytes_total == 120


def test_old_packets_are_pruned():
    extractor = SlidingWindowFeatureExtractor(window_seconds=5)
    extractor.add_packet(PacketRecord(10, "10.0.0.5", "10.0.0.1", 5000, 22, "S", 60))
    assert extractor.snapshot(now=20) == []
