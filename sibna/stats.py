try:
    from prometheus_client import Counter, Gauge
    ACTIVE_CONN = Gauge('obsidian_active_conn', 'Active secure tunnels')
except:
    class Mock:
        def inc(self): pass
        def dec(self): pass
    ACTIVE_CONN = Mock()