"""Command-line interface for netml library."""
import argparse
import importlib
import inspect
import itertools
import pkgutil
import tempfile
import textwrap

import argcmdr
import argparse_formatter
import numpy as np
import sklearn.model_selection
import terminaltables
import yaml

import netml.ndm
import netml.ndm.model
import netml.pparser.parser
from netml.utils.tool import dump_data, load_data, ManualDependencyError


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


NORMAL = 0
ABNORMAL = 1


# interface for setup.py

def execute():
    """launch the netml cli"""
    argcmdr.main(Main)


# utilities

def extract(pcap_file, label=None, label_file=None, *, random_state, verbosity):
    pp = netml.pparser.parser.PCAP(
        pcap_file,
        flow_ptks_thres=2,
        verbose=verbosity,
        random_state=random_state,
    )

    # extract flows from pcap
    pp.pcap2flows(q_interval=0.9)

    # label each flow
    if label is not None or label_file is not None:
        pp.label_flows(label_file=label_file, label=label)

    # extract features from each flow given feat_type
    pp.flow2features('IAT', fft=False, header=False)

    return pp


# commands

class Main(argcmdr.RootCommand):
    """detect novel or anomalous network activity from packet captures"""

    def __init__(self, parser):
        # FIXME: internals are way too verbose
        parser.add_argument(
            '-v', '--verbosity',
            type=int,
            default=1,
            metavar='INT',
            help="verbosity level (default: 1)",
        )
        parser.add_argument(
            '--random-state',
            metavar='INT',
            type=int,
            default=42,
            help="random state used in extraction and modeling (default: 42)",
        )


@Main.register
class Learn(argcmdr.Command):
    """train & test anomaly-detection models"""

    FEATURE_SPOOL_MAX_SIZE = 50 * 1024 ** 2  # 50 MB

    action_extract = 'extract'
    action_train = 'train'
    actions = (action_extract, action_train)

    train_algorithms = ('ocsvm', 'kde', 'if', 'ae', 'gmm', 'pca')

    formatter_class = argparse_formatter.ParagraphFormatter

    def __init__(self, parser):
        # input/output paths

        pcap_labeling = parser.add_argument_group(
            "pcap extraction & labeling",

            "Specify packet capture (pcap) file(s) from which to extract features.\n\n"

            "To test the model during the training phase, "
            "optionally specify labels (csv) file(s) with -l/--label, "
            "by which to label pcap files specified with -p/--pcap. "
            "Alternatively, specify NORMAL & ABNORMAL pcaps with "
            "--pcap-normal and --pcap-abnormal.\n\n"

            f'Note: at least one pcap file is required to "{self.action_extract}".'
        )
        pcap_labeling.add_argument(
            '-p', '--pcap',
            action='append',
            metavar='FILE',
            type=argparse.FileType('rb'),
            help=f'path(s) to packet capture (pcap) file(s)',
        )
        pcap_labeling.add_argument(
            '-l', '--label',
            action='append',
            metavar='FILE',
            type=argparse.FileType('r'),
            help='path(s) to labels (csv) file(s) to pair with pcap files specified by --pcap '
                 f'(optional for "{self.action_extract}" such that "{self.action_train}" '
                 'may subsequently test model)',
            # TODO: help=f'path to labels (csv) file (required to "{self.action_test}")',
        )
        pcap_labeling.add_argument(
            '--pcap-normal',
            action='append',
            metavar='FILE',
            type=argparse.FileType('rb'),
            help='path(s) to packet capture (pcap) file(s) '
                 'that will be labeled "normal" during testing',
        )
        pcap_labeling.add_argument(
            '--pcap-abnormal',
            action='append',
            metavar='FILE',
            type=argparse.FileType('rb'),
            help='path(s) to packet capture (pcap) file(s) '
                 'that will be labeled "abnormal" during testing',
        )

        feature_modeling = parser.add_argument_group(
            "features & model",
            "Specify paths at which to store extracted features and the trained model."
        )
        feature_modeling.add_argument(
            '-f', '--feature',
            metavar='FILE',
            type=argparse.FileType('w+b'),
            help=f"path at which extracted features are stored "
                 f'(required only to "{self.action_extract}" OR '
                 f'"{self.action_train}" *in isolation*)',
        )
        feature_modeling.add_argument(
            '-o', '--output',
            '-m', '--model',
            metavar='FILE',
            type=argparse.FileType('wb'),
            help="path at which to store trained model "
                 f'(required to "{self.action_train}")',
        )

        model_params = parser.add_argument_group(
            "modeling",
            "Configure model training."
        )
        model_params.add_argument(
            '--algorithm',
            choices=self.train_algorithms,
            default=self.train_algorithms[0],
            help=f"model-training algorithm to use (default: {self.train_algorithms[0]})",
        )
        model_params.add_argument(
            '--help-algorithm',
            action='store_true',
            help="describe model-training algorithms and exit",
        )
        model_params.add_argument(
            '--param',
            metavar='YAML',
            type=yaml.safe_load,
            help="algorithmic parameters to override defaults (YAML/JSON text or path to file)",
        )
        model_params.add_argument(
            '--help-param',
            action='store_true',
            help="show all model parameters & defaults and exit",
        )
        model_params.add_argument(
            '--test-size',
            metavar='FLOAT',
            type=float,
            default=0.33,
            help="test size used in train-test-split (default: 0.33)",
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

        # add'l help
        if args.help_algorithm:
            self.print_help_algorithm()
            return

        if args.help_param:
            self.print_help_param()
            return

        # dynamic argument checks
        if (self.action_extract in actions and not args.pcap
                                           and not args.pcap_normal
                                           and not args.pcap_abnormal):
            parser.error(f'at least one of the following arguments are required to '
                         f'"{self.action_extract}": -p/--pcap, --pcap-normal or --pcap-abnormal')

        if args.label and len(args.label) != len(args.pcap):
            parser.error("the number of files optionally specified by -l/--label must match those "
                         "specified by -p/--pcap")

        if args.pcap and not args.label and (args.pcap_normal or args.pcap_abnormal):
            parser.error("may not specify --pcap and --pcap-normal/--pcap-abnormal without also "
                         "specifying --label (both labeled and unlabeled pcaps)")

        if actions != self.actions and not args.feature:
            parser.error(f'the following arguments are required to "{self.action_extract}" or '
                         f'"{self.action_train}" in isolation: -f/--feature')

        if self.action_train in actions and not args.output:
            parser.error(f'the following arguments are required to "{self.action_train}": '
                         f'-o/--output/-m/--model')

        # dynamic argument defaults
        feature_descriptor = (
            args.feature or
            tempfile.SpooledTemporaryFile(max_size=self.FEATURE_SPOOL_MAX_SIZE)
        )

        # actions
        if self.action_extract in actions:
            pcaps = args.pcap or ()
            labels = ({'label_file': label} for label in args.label or itertools.repeat(None))

            pcaps_normal = args.pcap_normal or ()
            labels_normal = ({'label': NORMAL} for _count in itertools.count())

            pcaps_abnormal = args.pcap_abnormal or ()
            labels_abnormal = ({'label': ABNORMAL} for _count in itertools.count())

            self.extract(
                itertools.chain(
                    zip(pcaps, labels),
                    zip(pcaps_normal, labels_normal),
                    zip(pcaps_abnormal, labels_abnormal),
                ),
                feature_descriptor,
            )

        if self.action_train in actions:
            self.train(
                feature_descriptor,
                args.output,
            )

    def extract(self, pcap_file_labels, feature_file):
        pcaps = [
            extract(
                pcap_file,
                random_state=self.args.random_state,
                verbosity=self.args.verbosity,
                **label_kwargs
            )
            for (pcap_file, label_kwargs) in pcap_file_labels
        ]

        pcap_count = len(pcaps)
        if pcap_count == 1:
            (pcap,) = pcaps
            (features, labels) = (pcap.features, pcap.labels)
        elif pcap_count > 1:
            # TODO: ensure that there is no normalization issue or other issue
            # TODO: with simply concatenating features this way
            #
            # (If that is the case, can perhaps merge data prior to generating features.
            # Iff concatenation is moved into PCAP class -- in an __add__ or otherwise --
            # and merge must occur before feature generation, then some guards and/or
            # refactoring might be necessary. Note that merge might make sense at packet
            # level or with flows.)
            features = np.concatenate([pcap.features for pcap in pcaps])

            if any(pcap.labels is None for pcap in pcaps):
                labels = None
            else:
                labels = np.concatenate([pcap.labels for pcap in pcaps])
        else:
            raise ValueError("nothing to extract")

        # NOTE: SpooledTemporaryFile is a useful (internal) interface, and which keeps data in
        # NOTE: memory until it's large enough that it "should" be written to disk. Its performance
        # NOTE: is *likely* sufficient; but, this *could* be replaced with a slightly more complex
        # NOTE: handling, so as to avoid (de)-serialization of the pickle when it's not required.
        dump_data((features, labels), out_file=feature_file)

        # for next step (if any):
        feature_file.seek(0)

    def train(self, feature_file, output_file):
        (features, labels) = load_data(feature_file)

        # train (and test split)
        #
        # TODO: might make sense to split testing into a separate "action," such that
        # TODO: it's done by default, but also can be applied modularly (on its own)
        #
        if labels is None:
            features_train = features
            features_test = labels_test = _labels_train = None

            if self.args.verbosity > 1:
                print(
                    terminaltables.AsciiTable([
                        ('', 'features', 'labels'),
                        ('train', features_train.shape, 'n/a'),
                        ('test', 'n/a', 'n/a'),
                    ], title='data shapes').table
                )
        else:
            (
                features_train,
                features_test,
                _labels_train,
                labels_test,
            ) = sklearn.model_selection.train_test_split(features,
                                                         labels,
                                                         test_size=self.args.test_size,
                                                         random_state=self.args.random_state)

            if self.args.verbosity > 1:
                print(
                    terminaltables.AsciiTable([
                        ('', 'features', 'labels'),
                        ('train', features_train.shape, 'n/a'),
                        ('test', features_test.shape, labels_test.shape),
                    ], title='data shapes').table
                )

        if self.args.verbosity > 1:
            print(f'model name: {self.args.algorithm}')

        # param may be:
        # * unspecified (None)
        # * just a dict for this model
        # * dict with sub-dicts for many models
        params = self.args.param or {}
        if isinstance(params.get(self.args.algorithm), dict):
            params = params[self.args.algorithm]

        if self.args.verbosity > 1:
            print(f'param override: {params}')

        model_class = self.load_algorithmic_model(self.args.algorithm)

        try:
            inspect.signature(model_class).bind(**params)
        except TypeError as exc:
            raise ValueError(
                f"model-training params failed to bind for {self.args.algorithm}:\n" +
                textwrap.indent(yaml.dump(params).strip(), '  ')
            ) from exc

        # create detection model
        model = model_class(
            random_state=self.args.random_state,
            **params
        )
        model.name = self.args.algorithm  # FIXME
        ndm = netml.ndm.model.MODEL(
            model,
            score_metric='auc',
            verbose=self.args.verbosity,
            random_state=self.args.random_state,
        )

        # train the model from the train set
        ndm.train(features_train)
        time_train = ndm.train.tot_time

        # evaluate the model
        if features_test is not None and labels_test is not None:
            ndm.test(features_test, labels_test)
            time_test = ndm.test.tot_time
        else:
            time_test = None

        # dump data to disk
        dump_data((model, ndm.history), out_file=output_file)

        # FIXME?: (file handlers otherwise closed at exit; but, this doesn't work for tests)
        output_file.close()

        if self.args.verbosity > 0:
            print(
                terminaltables.AsciiTable([
                    ('train time (s)', 'test time (s)', 'model score (auc)'),
                    (
                        time_train,
                        'n/a' if time_test is None else time_test,
                        getattr(ndm, 'score', 'n/a'),
                    ),
                ], title='training performance').table
            )

    def print_help_algorithm(self, title_addendum='', include_docs=True):
        print(f"{self.args.__parser__.prog}: model-training algorithms", title_addendum)

        for (model_name, model_class) in self.load_algorithmic_model().items():
            print('\n', model_name, ':', sep='')

            if isinstance(model_class, ManualDependencyError):
                print('  [Algorithm could not be loaded due to missing dependencies]', end='\n\n')
                print(textwrap.indent(str(model_class), '  '))

                continue

            # defaults as they might be overridden in yaml
            model_signature = inspect.signature(model_class)
            model_defaults = {
                parameter.name: parameter.default
                for parameter in model_signature.parameters.values()
            }
            print(textwrap.indent(yaml.dump(model_defaults).strip(), '  '))

            if include_docs:
                print('\n  ---', end='\n\n')

                # documentation
                doc = model_class.__doc__ or model_class.__init__.__doc__

                # fix indentation
                #
                # first line may not be indented at all
                if doc[0] in (' ', '\n'):
                    doc = textwrap.dedent(doc)
                else:
                    line_end = doc.find('\n') + 1
                    if line_end > 1:
                        doc = doc[:line_end] + textwrap.dedent(doc[line_end:])

                print(textwrap.indent(doc.strip(), '  '))

    def print_help_param(self):
        self.print_help_algorithm(
            title_addendum='(params only)',
            include_docs=False,
        )

    def load_algorithmic_model(self, model_name=None):
        models = {}

        # module names *should* be same as algorithm & class but we allow them to differ
        # NOTE: could simplify this by just mandating that module names equal to model class names
        for module_info in pkgutil.iter_modules(netml.ndm.__path__):
            if module_info.name == 'model':
                # NOTE: could just move this module aside
                continue

            try:
                module = importlib.import_module(f'netml.ndm.{module_info.name}')
            except ManualDependencyError as exc:
                # in the case of printing help we'll just report this algo as unconfigured
                # so: defer to caller
                models[module_info.name] = exc
                found = module_info.name
            else:
                try:
                    # optimistic naming for most models
                    models[module_info.name] = getattr(module, module_info.name.upper())
                    found = module_info.name
                except AttributeError:
                    # fallback to iteration over all possibilities
                    for algorithm in self.train_algorithms:
                        if algorithm in models:
                            continue

                        try:
                            models[algorithm] = getattr(module, algorithm.upper())
                        except AttributeError:
                            pass
                        else:
                            found = algorithm
                            break

            if found == model_name:
                return models[model_name]
        else:
            if model_name:
                raise LookupError(f"could not find algorithmic model: {model_name}")

        missing_models = set(self.train_algorithms) - models.keys()
        if missing_models:
            raise LookupError(f"failed to load algorithm models: {missing_models}")

        unexpected_models = models.keys() - set(self.train_algorithms)
        if unexpected_models:
            # this isn't really a big deal -- can exclude -- but shouldn't happen for now
            raise RuntimeError(f"unanticipated models loaded: {unexpected_models}")

        return models
