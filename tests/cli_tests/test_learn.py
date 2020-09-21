"""Tests for the CLI sub-command `learn`"""
import contextlib
import io
import pathlib
import tempfile
import unittest
import warnings

import argcmdr

from netml import cli
from netml.utils.tool import load_data


# TODO: use smaller data files to speed up tests?

DATA_PATH = pathlib.Path(__file__).parent.parent.parent / 'examples' / 'data'

TEMPDIR_PATH = pathlib.Path(tempfile.gettempdir())


def setUpModule():
    warnings.simplefilter('ignore', ResourceWarning)


class CLITestCase(unittest.TestCase):

    def try_execute(self, *argv):
        argcmdr.main(cli.Main, argv=map(str, argv))


class TestLearnExtractRequirements(CLITestCase):

    def test_extract_requires_pcap(self):
        """extract requires a pcap path"""
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr), \
             self.assertRaises(SystemExit) as context:
            self.try_execute(
                'learn',
                'extract',
                '-f', TEMPDIR_PATH / 'netml-test-features-a',
            )

        self.assertEqual(context.exception.code, 2)
        self.assertRegex(stderr.getvalue(), r'arguments are required .+: -p/--pcap')

    def test_extract_requires_features(self):
        """extract-only requires a features path"""
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr), \
             self.assertRaises(SystemExit) as context:
            self.try_execute(
                'learn',
                'extract',
                '-p', DATA_PATH / 'demo.pcap',
            )

        self.assertEqual(context.exception.code, 2)
        self.assertRegex(stderr.getvalue(), r'arguments are required .+: -f/--feature')

    def test_extract_requires_model(self):
        """extract-train requires a model output path"""
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr), \
             self.assertRaises(SystemExit) as context:
            self.try_execute(
                'learn',
                '-p', DATA_PATH / 'demo.pcap',
            )

        self.assertEqual(context.exception.code, 2)
        self.assertRegex(stderr.getvalue(), r'arguments are required .+: -o/--output/-m/--model')


class TestLearnExtractPcapOnly(CLITestCase):

    def test_extract_only(self):
        """extract features to path"""
        feature_path = TEMPDIR_PATH / 'netml-test-features-a'

        self.try_execute(
            'learn',
            'extract',
            '-p', DATA_PATH / 'demo.pcap',
            '-f', feature_path,
        )

        (features, labels) = load_data(feature_path)

        self.assertGreater(len(features), 0)
        self.assertIsNone(labels)

    def test_extract_train(self):
        """extract features and train model"""
        model_path = TEMPDIR_PATH / 'netml-test-output-a'

        self.try_execute(
            'learn',
            '-p', DATA_PATH / 'demo.pcap',
            '-o', model_path,
        )

        (model, train_history) = load_data(model_path)

        self.assertTrue(hasattr(model, 'predict'))
        self.assertFalse(train_history)

    def test_extract_multiple(self):
        """extract features from multiple unlabeled pcap files"""
        feature_path = TEMPDIR_PATH / 'netml-test-features-a'

        self.try_execute(
            'learn',
            'extract',
            '-f', feature_path,

            # (filenames reflect what's in them but here we specify no labels for testing)
            '-p', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.119_anomaly.pcap',
            '-p', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.1_normal.pcap',
        )

        (features, labels) = load_data(feature_path)

        self.assertEqual(len(features), 5_289)
        self.assertIsNone(labels)


class TestLearnExtractPcapLabels(CLITestCase):

    def test_extract_only(self):
        """extract features & labels to path"""
        feature_path = TEMPDIR_PATH / 'netml-test-features-a'

        self.try_execute(
            'learn',
            'extract',
            '-p', DATA_PATH / 'demo.pcap',
            '-l', DATA_PATH / 'demo.csv',
            '-f', feature_path,
        )

        (features, labels) = load_data(feature_path)

        self.assertEqual(len(features), 88)
        self.assertEqual(len(labels), 88)

    def test_extract_train(self):
        """extract features & labels and train & test model"""
        model_path = TEMPDIR_PATH / 'netml-test-output-a'

        self.try_execute(
            'learn',
            '-p', DATA_PATH / 'demo.pcap',
            '-l', DATA_PATH / 'demo.csv',
            '-o', model_path,
        )

        (model, train_history) = load_data(model_path)

        self.assertTrue(hasattr(model, 'predict'))

        self.assertIsNot(train_history, None)
        self.assertIn('score', train_history)
        self.assertGreater(train_history['score'], 0)

    def test_extract_multiple(self):
        """extract features & labels from multiple pcap & label files"""
        feature_path = TEMPDIR_PATH / 'netml-test-features-a'

        self.try_execute(
            'learn',
            'extract',
            '-f', feature_path,

            '-p', DATA_PATH / 'demo.pcap',
            '-p', DATA_PATH / 'demo.pcap',

            '-l', DATA_PATH / 'demo.csv',
            '-l', DATA_PATH / 'demo.csv',
        )

        (features, labels) = load_data(feature_path)

        self.assertEqual(len(features), 176)
        self.assertEqual(len(labels), 176)

    def test_extract_mismatch_length_0(self):
        """cannot specify too many label files for pcap files"""
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr), \
             self.assertRaises(SystemExit) as context:
            self.try_execute(
                'learn',
                'extract',
                '-f', TEMPDIR_PATH / 'netml-test-features-a',

                '-p', DATA_PATH / 'demo.pcap',

                '-l', DATA_PATH / 'demo.csv',
                '-l', DATA_PATH / 'demo.csv',
            )

        self.assertEqual(context.exception.code, 2)
        self.assertRegex(stderr.getvalue(), r'number of files .+ must match')

    def test_extract_mismatch_length_1(self):
        """cannot specify too few label files for pcap files"""
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr), \
             self.assertRaises(SystemExit) as context:
            self.try_execute(
                'learn',
                'extract',
                '-f', TEMPDIR_PATH / 'netml-test-features-a',

                '-p', DATA_PATH / 'demo.pcap',
                '-p', DATA_PATH / 'demo.pcap',

                '-l', DATA_PATH / 'demo.csv',
            )

        self.assertEqual(context.exception.code, 2)
        self.assertRegex(stderr.getvalue(), r'number of files .+ must match')


class TestLearnExtractPcapNormalAbnormal(CLITestCase):

    def test_extract_only(self):
        """extract flag-labeled features to path"""
        feature_path = TEMPDIR_PATH / 'netml-test-features-a'

        self.try_execute(
            'learn',
            'extract',

            '--pcap-normal', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.1_normal.pcap',
            '--pcap-abnormal', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.119_anomaly.pcap',

            '-f', feature_path,
        )

        (features, labels) = load_data(feature_path)

        self.assertEqual(len(features), 5289)
        self.assertEqual(len(labels), 5289)

        # 0 is normal
        self.assertFalse(labels[:4979].any())

        # 1 is abnormal
        self.assertTrue(labels[4979:].all())

    def test_extract_train(self):
        """extract flag-labeled features and train & test model"""
        model_path = TEMPDIR_PATH / 'netml-test-output-a'

        self.try_execute(
            'learn',

            '--pcap-normal', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.1_normal.pcap',
            '--pcap-abnormal', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.119_anomaly.pcap',

            '-o', model_path,
        )

        (model, train_history) = load_data(model_path)

        self.assertTrue(hasattr(model, 'predict'))

        self.assertIsNot(train_history, None)
        self.assertIn('score', train_history)
        self.assertGreater(train_history['score'], 0)


class TestLearnExtractPcapMixed(CLITestCase):

    def test_extract_only(self):
        """extract file-labeled & flag-labeled features to path"""
        feature_path = TEMPDIR_PATH / 'netml-test-features-a'

        self.try_execute(
            'learn',
            'extract',

            '-p', DATA_PATH / 'demo.pcap',
            '-l', DATA_PATH / 'demo.csv',

            '--pcap-normal', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.1_normal.pcap',
            '--pcap-abnormal', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.119_anomaly.pcap',

            '-f', feature_path,
        )

        (features, labels) = load_data(feature_path)

        self.assertEqual(len(features), 88 + 4979 + 310)
        self.assertEqual(len(labels), 88 + 4979 + 310)

        # 0 is normal; 1 is abnormal
        self.assertTrue(labels[:88].any())
        self.assertFalse(labels[:88].all())

        self.assertFalse(labels[88:4979].any())

        self.assertTrue(labels[(88 + 4979):].all())

    def test_extract_train(self):
        """extract file-labeled & flag-labeled features and train & test model"""
        model_path = TEMPDIR_PATH / 'netml-test-output-a'

        self.try_execute(
            'learn',

            '-p', DATA_PATH / 'demo.pcap',
            '-l', DATA_PATH / 'demo.csv',

            '--pcap-normal', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.1_normal.pcap',
            '--pcap-abnormal', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.119_anomaly.pcap',

            '-o', model_path,
        )

        (model, train_history) = load_data(model_path)

        self.assertTrue(hasattr(model, 'predict'))

        self.assertIsNot(train_history, None)
        self.assertIn('score', train_history)
        self.assertGreater(train_history['score'], 0)

    def test_unlabeled_pcap(self):
        """cannot specify unlabeled pcap & flag-labeled pcap(s)"""
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr), \
             self.assertRaises(SystemExit) as context:
            self.try_execute(
                'learn',
                'extract',
                '-f', TEMPDIR_PATH / 'netml-test-features-a',

                '-p', DATA_PATH / 'demo.pcap',
                '--pcap-normal', DATA_PATH / 'srcIP_10.42.0.1' / 'srcIP_10.42.0.1_normal.pcap',
            )

        self.assertEqual(context.exception.code, 2)
        self.assertIn(
            'may not specify --pcap and --pcap-normal/--pcap-abnormal '
            'without also specifying --label',
            stderr.getvalue()
        )
