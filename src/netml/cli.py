"""Command-line interface for netml library."""
import tempfile

import argcmdr
import argparse
import sklearn.model_selection

import netml.ndm.model
import netml.ndm.ocsvm
import netml.pparser.parser
from netml.utils.tool import dump_data, load_data


#
# NOTE: This module is currently considered to be in DEMO state -- as yet, it
# NOTE: mirrors examples via a console interface, with limited configurability.
#
# NOTE: That said, it shouldn't take much for it to be brought to minimum
# NOTE: viability.
#

# TODO: (sub)-command to quickly/easily get command-line completion?
#
# (likely shouldn't do anything to system, but could at least call out to
# register-python-argcomplete?)


def execute():
    """launch the netml cli"""
    argcmdr.main(Main)


class Main(argcmdr.Command):
    """detect novel or anomalous network activity from packet captures"""

    FEATURE_SPOOL_MAX_SIZE = 50 * 1024 ** 2  # 50 MB

    action_extract = 'extract'
    action_analyze = 'analyze'
    actions = (action_extract, action_analyze)

    def __init__(self, parser):
        # input/output paths
        parser.add_argument(
            '-p', '--pcap',
            type=argparse.FileType('rb'),
            help=f'path to packet capture (pcap) file (required to "{self.action_extract}")',
        )
        parser.add_argument(
            '-l', '--label',
            type=argparse.FileType('r'),
            help=f'path to labels (csv) file (required to "{self.action_extract}")',
        )
        parser.add_argument(
            '-f', '--feature',
            type=argparse.FileType('w+b'),
            help=f"path at which extracted features are stored "
                 f'(required to "{self.action_extract}" OR "{self.action_analyze}" *in isolation*)',
        )
        parser.add_argument(
            '-o', '--output',
            type=argparse.FileType('wb'),
            help="path at which to store analysis results "
                 f'(required to "{self.action_analyze}")',
        )

        # specify step (optionally)
        parser.add_argument(
            'action',
            choices=self.actions,
            nargs='?',
            help="action to take (default: all)",
        )

    def __call__(self, args, parser):
        actions = (args.action,) if args.action else self.actions

        # dynamic argument checks
        if self.action_extract in actions and (not args.pcap or not args.label):
            parser.error(f'the following arguments are required to "{self.action_extract}": '
                         f"-p/--pcap, -l/--label")

        if actions != self.actions and not args.feature:
            parser.error(f'the following arguments are required to "{self.action_extract}" or '
                         f'"{self.action_analyze}" in isolation: -f/--feature')

        if self.action_analyze in actions and not args.output:
            parser.error(f'the following arguments are required to "{self.action_analyze}": '
                         f'-o/--output')

        # dynamic argument defaults
        feature_descriptor = (
            args.feature or
            tempfile.SpooledTemporaryFile(max_size=self.FEATURE_SPOOL_MAX_SIZE)
        )

        # actions
        if self.action_extract in actions:
            self.extract(
                args.pcap,
                args.label,
                feature_descriptor,
            )

        if self.action_analyze in actions:
            self.analyze(
                feature_descriptor,
                args.output,
            )

    @staticmethod
    def extract(pcap, label, feature):
        # FIXME: demo
        pp = netml.pparser.parser.PCAP(
            pcap,
            flow_ptks_thres=2,
            verbose=3,
            random_state=42,
        )

        # extract flows from pcap
        pp.pcap2flows(q_interval=0.9)

        # label each flow with a label
        pp.label_flows(label_file=label)

        # extract features from each flow given feat_type
        pp.flow2features('IAT', fft=False, header=False)

        # SpooledTemporaryFile is a useful (internal) interface, and which keeps data in memory
        # until it's large enough that it "should" be written to disk. Its performance is *likely*
        # sufficient; but, this *could* be replaced with a slightly more complex handling, so as to
        # avoid (de)-serialization of the pickle when it's not required.
        dump_data((pp.features, pp.labels), out_file=feature)

        # for next step (if any):
        feature.seek(0)

    @staticmethod
    def analyze(feature, output):
        # FIXME: demo
        (X, y) = load_data(feature)

        # split train and test test
        (
            X_train,
            X_test,
            y_train,
            y_test,
        ) = sklearn.model_selection.train_test_split(X, y, test_size=0.33, random_state=42)

        # print(f'X_train.shape: {X_train.shape}, X_test.shape: {X_test.shape}, y_train.shape: {y_train.shape}, '
        #       f'y_test.shape: {y_test.shape}')

        # model_name in ['OCSVM', 'KDE','IF', 'AE', 'GMM', 'PCA']
        model_name = 'OCSVM'
        print(f'model_name: {model_name}')
        # create detection model
        # model = generate_model(model_name)
        model = netml.ndm.ocsvm.OCSVM(kernel='rbf', nu=0.5, random_state=42)
        model.name = model_name
        ndm = netml.ndm.model.MODEL(model, score_metric='auc', verbose=3, random_state=42)

        # learned the model from the train set
        ndm.train(X_train)

        # evaluate the learned model
        ndm.test(X_test, y_test)

        # dump data to disk
        dump_data((model, ndm.history), out_file=output)

        print(ndm.train.tot_time, ndm.test.tot_time, ndm.score)
