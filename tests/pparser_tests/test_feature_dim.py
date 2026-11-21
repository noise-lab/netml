"""flow2features(dim=...) fixes the number of features per flow across captures."""
import pathlib
import unittest

import numpy as np

from netml.pparser.parser import PCAP

DATA = pathlib.Path(__file__).parent.parent.parent / 'examples' / 'data' / 'srcIP_10.42.0.1'
PCAPS = [DATA / 'srcIP_10.42.0.119_anomaly.pcap', DATA / 'srcIP_10.42.0.1_normal.pcap']


def flows(path):
    pcap = PCAP(str(path), flow_ptks_thres=2, verbose=0)
    pcap.pcap2flows(q_interval=0.9)
    return pcap


class TestFeatureDim(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pcaps = [flows(p) for p in PCAPS]

    def test_default_width_depends_on_capture(self):
        """without dim, these two captures yield different widths (the motivating case)"""
        widths = set()
        for pcap in self.pcaps:
            pcap.flow2features('IAT')
            self.assertEqual(pcap.features.shape[1], pcap.dim)
            widths.add(pcap.dim)
        self.assertEqual(len(widths), 2)

    def test_shared_dim_gives_same_width(self):
        first = self.pcaps[0]
        first.flow2features('IAT')
        dim = first.dim
        for pcap in self.pcaps[1:]:
            pcap.flow2features('IAT', dim=dim)
            self.assertEqual(pcap.features.shape[1], dim)
        stacked = np.concatenate([p.features for p in self.pcaps])
        self.assertEqual(stacked.shape[1], dim)

    def test_explicit_dim_pads_and_truncates(self):
        pcap = self.pcaps[1]
        for dim in (1, 3, 50):
            pcap.flow2features('IAT', dim=dim)
            self.assertEqual(pcap.features.shape[1], dim)
            self.assertEqual(pcap.dim, dim)

    def test_header_width_follows_dim(self):
        pcap = self.pcaps[0]
        pcap.flow2features('IAT', header=True, dim=5)
        self.assertEqual(pcap.features.shape[1], (8 + 5) + 5)

    def test_invalid_dim(self):
        pcap = self.pcaps[0]
        for bad in (0, -3, 2.5, True, '4'):
            with self.assertRaises(ValueError):
                pcap.flow2features('IAT', dim=bad)
        with self.assertRaises(ValueError):
            pcap.flow2features('STATS', dim=5)
        pcap.flow2features('STATS', dim=12)
        self.assertEqual(pcap.features.shape[1], 12)


if __name__ == '__main__':
    unittest.main()
