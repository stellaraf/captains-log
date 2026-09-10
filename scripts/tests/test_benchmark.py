import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import benchmark


class BenchmarkGuards(unittest.TestCase):
    def test_credentials_require_private_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"env"
            path.write_text("CH_PASSWORD=test-only\n")
            path.chmod(0o600)
            self.assertEqual(benchmark.secure_env(path)["CH_PASSWORD"],"test-only")
            path.chmod(0o640)
            with self.assertRaises(benchmark.StopBenchmark):benchmark.secure_env(path)
            path.chmod(0o600)
            link=Path(directory)/"link";link.symlink_to(path)
            with self.assertRaises(benchmark.StopBenchmark):benchmark.secure_env(link)

    def test_remote_endpoint_refused_before_credentials(self):
        with self.assertRaises(benchmark.StopBenchmark):
            benchmark.ClickHouse(Path("missing"),"http://192.0.2.1:8123")

    def test_projected_temp_bytes_count_toward_disk_budget(self):
        state={"bytes":19*benchmark.GIB,"host_free_bytes":40*benchmark.GIB,"database_free_bytes":100*benchmark.GIB}
        with patch.object(benchmark,"table_state",return_value=state):
            with self.assertRaises(benchmark.StopBenchmark):
                benchmark.safety(None,20*benchmark.GIB,30*benchmark.GIB,projected_batch_bytes=2*benchmark.GIB)

    def test_host_reserve_is_independent_of_table_budget(self):
        state={"bytes":0,"host_free_bytes":29*benchmark.GIB,"database_free_bytes":100*benchmark.GIB}
        with patch.object(benchmark,"table_state",return_value=state):
            with self.assertRaises(benchmark.StopBenchmark):benchmark.safety(None,20*benchmark.GIB,30*benchmark.GIB)

    def cleanup_case(self,responses):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"receipt.json"
            path.write_text(json.dumps({"table":benchmark.TABLE,"checkpoints":[{"rows":10}]}))
            args=argparse.Namespace(output=path,env_file=Path("unused"),endpoint="http://127.0.0.1:28123")
            ch=Mock();ch.rows.side_effect=responses
            with patch.object(benchmark,"ClickHouse",return_value=ch):
                with self.assertRaises(benchmark.StopBenchmark):benchmark.cleanup(args)
            ch.execute.assert_not_called()

    def test_cleanup_rejects_foreign_marker(self):
        self.cleanup_case([[{"comment":"unrelated table"}]])

    def test_cleanup_rejects_foreign_rows(self):
        self.cleanup_case([[{"comment":benchmark.MARKER}],[{"rows":10,"foreign_rows":1}]])

    def test_cleanup_rejects_active_insert(self):
        self.cleanup_case([[{"comment":benchmark.MARKER}],[{"rows":10,"foreign_rows":0}],[{"count":1}]])

    def test_cleanup_requires_completed_measurement_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"receipt.json";path.write_text(json.dumps({"table":benchmark.TABLE}))
            with patch.object(benchmark,"ClickHouse") as ch:
                with self.assertRaises(benchmark.StopBenchmark):benchmark.cleanup(argparse.Namespace(output=path))
                ch.assert_not_called()


if __name__=="__main__":unittest.main()
