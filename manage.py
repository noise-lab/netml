"""repository management tasks"""
import copy
import re

from argcmdr import Local, LocalRoot


class Manage(LocalRoot):
    """manage the library repository"""


@Manage.register
class Version(Local):
    """bump package version (and optionally build and release)"""

    bump_default_message = "Bump version: {current_version} → {new_version}"

    def __init__(self, parser):
        parser.add_argument(
            'part',
            choices=('major', 'minor', 'patch'),
            help="part of the version to be bumped",
        )
        parser.add_argument(
            '-m', '--message',
             help=f"Tag message (in addition to default: "
                  f"'{self.bump_default_message}')",
        )

        parser.add_argument(
            '--build',
            action='store_true',
            help='build the new version',
        )
        parser.add_argument(
            '--release',
            action='store_true',
            help='release the new build',
        )

    def prepare(self, args, parser):
        if args.message:
            tag_message = f"{self.bump_default_message}\n\n{args.message}"
        else:
            tag_message = self.bump_default_message

        (_code,
         stdout,
         _err) = yield self.local['bumpversion'][
            '--tag-message', tag_message,
            '--list',
            args.part,
        ]

        if args.build:
            yield self.root['build'].prepare()

            if args.release:
                rel_args = copy.copy(args)
                if stdout is None:
                    rel_args.version = ('DRY-RUN',)
                else:
                    (version_match,) = re.finditer(
                        r'^new_version=([\d.]+)$',
                        stdout,
                        re.M,
                    )
                    rel_args.version = version_match.groups()
                yield self.root['release'].prepare(rel_args)
        elif args.release:
            parser.error('will not release package without build')


@Manage.register
class Build(Local):
    """build package"""

    def prepare(self):
        return self.local.FG, self.local['python'][
            'setup.py',
            'sdist',
            'bdist_wheel',
        ]


@Manage.register
class Release(Local):
    """upload package(s) to pypi"""

    # TODO: add support for upload to test.pypi.org
    # (See also: https://github.com/bast/pypi-howto)
    #
    # NOTE: also, could set up a Github workflow that automatically builds for
    # us, (triggered by say a tag or *maybe* even a push); perhaps stores that
    # artifact in Github Packages; and even uploads it to PyPI, or at least to
    # test.pypi.org.
    # (This might be convenient. It also might alleviate set-up work -- and any
    # concerns -- over credentials sharing.)
    # (See also: https://packaging.python.org/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/)

    def __init__(self, parser):
        parser.add_argument(
            'version',
            nargs='*',
        )

    def prepare(self, args):
        if args.version:
            target = [f'dist/*{version}*' for version in args.version]
        else:
            target = 'dist/*'
        return self.local.FG, self.local['twine']['upload'][target]
