"""Every NDM detector must score anomalies higher than normal points.

netml's detectors follow pyod's convention: ``decision_function`` returns
larger values for more anomalous samples, so ``roc_auc_score(y, scores)``
with anomalies labelled 1 is well above 0.5 on easy data.
"""
import unittest

import numpy as np
from sklearn.metrics import roc_auc_score

from netml.ndm.gmm import GMM
from netml.ndm.iforest import IF
from netml.ndm.kde import KDE
from netml.ndm.ocsvm import OCSVM
from netml.ndm.pca import PCA


def make_data(seed=0):
    rng = np.random.default_rng(seed)
    train = rng.normal(0, 1, size=(300, 4))
    normal = rng.normal(0, 1, size=(100, 4))
    anomalies = rng.normal(6, 1, size=(20, 4))
    X_test = np.vstack([normal, anomalies])
    y_test = np.r_[np.zeros(len(normal)), np.ones(len(anomalies))]
    return train, X_test, y_test


class TestScoreOrientation(unittest.TestCase):

    def assert_anomalies_score_higher(self, model):
        X_train, X_test, y_test = make_data()
        model.fit(X_train)
        scores = model.decision_function(X_test)
        auc = roc_auc_score(y_test, scores)
        self.assertGreater(auc, 0.9, f'{type(model).__name__} AUC {auc:.3f}: scores inverted?')

    def test_iforest(self):
        self.assert_anomalies_score_higher(IF(verbose=0))

    def test_ocsvm(self):
        self.assert_anomalies_score_higher(OCSVM())

    def test_gmm(self):
        self.assert_anomalies_score_higher(GMM())

    def test_kde(self):
        self.assert_anomalies_score_higher(KDE())

    def test_pca(self):
        self.assert_anomalies_score_higher(PCA())


if __name__ == '__main__':
    unittest.main()
