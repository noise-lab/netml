"""random_state is accepted, with a warning, by detectors that ignore it."""
import unittest
import warnings

from netml.ndm.kde import KDE
from netml.ndm.model import MODEL
from netml.ndm.ocsvm import OCSVM


def named(model):
    model.name = type(model).__name__
    return model


class TestIgnoredRandomState(unittest.TestCase):

    def test_warns_when_ignored(self):
        for make in (lambda: OCSVM(random_state=1), lambda: KDE(random_state=1)):
            with self.assertWarns(UserWarning):
                make()

    def test_model_wrapper_warns(self):
        with self.assertWarns(UserWarning):
            MODEL(named(OCSVM()), random_state=1)

    def test_no_warning_without_random_state(self):
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            OCSVM()
            KDE()
            MODEL(named(OCSVM()))

    def test_typo_is_rejected(self):
        with self.assertRaises(TypeError):
            OCSVM(random_stat=1)
        with self.assertRaises(TypeError):
            KDE(bandwith=0.5)


if __name__ == '__main__':
    unittest.main()
