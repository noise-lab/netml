"""Tests for the CLI sub-command `classify`"""
import contextlib
import io
import pathlib
import tempfile
import unittest
import warnings

import argcmdr

from netml import cli
from netml.utils.tool import load_data

DATA_PATH = pathlib.Path(__file__).parent.parent.parent / 'examples' / 'data' / 'srcIP_10.42.0.1'

TEMPDIR_PATH = pathlib.Path(tempfile.gettempdir())


def setUpModule():
    warnings.simplefilter('ignore', ResourceWarning)


class TestClassifyFeatureDim(unittest.TestCase):

    def try_execute(self, *argv):
        argcmdr.main(cli.Main, argv=map(str, argv))

    def test_classify_pcap_with_different_native_width(self):
        """a pcap is classified at the trained model's width, not its own"""
        model_path = TEMPDIR_PATH / 'netml-test-classify-model'

        # the normal capture alone yields a different IAT width than the anomaly capture
        self.try_execute(
            'learn',
            '-p', DATA_PATH / 'srcIP_10.42.0.1_normal.pcap',
            '-o', model_path,
        )
        (model, _history) = load_data(model_path)
        self.assertEqual(cli.trained_feature_dim(model), model.n_features_in_)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.try_execute(
                'classify',
                '-m', model_path,
                '-p', DATA_PATH / 'srcIP_10.42.0.119_anomaly.pcap',
            )


if __name__ == '__main__':
    unittest.main()
