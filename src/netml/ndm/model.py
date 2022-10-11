"""Detection model
    train and test a model on a given data
"""
# Authors: kun.bj@outlook.com
#
# License: xxx

from sklearn import metrics
from sklearn.metrics import roc_curve

from netml.utils.tool import timing


class MODEL:

    def __init__(self, model=None, *, score_metric='auc', verbose=1, random_state=42):
        """Train and test a model on a given data.

        Parameters
        ----------
        model: instance
            a detection model instance.

        score_metric: str (default is 'auc')
            a score we used to evaluate the model

        verbose: int (default is 1)
            a print level is to control what information should be printed according to the given value.
            The higher the value is, the more info is printed.

        random_state: int
            a value is to make your experiments more reproducible.

        Returns
        -------
            a MODEL instance
        """

        self.model = model
        self.model_name = model.name
        self.score_metric = score_metric
        self.verbose = verbose
        self.random_state = random_state
        # store all data generated during training and testing the model.
        self.history = {}

    @timing
    def _train(self, X_train, y_train=None):
        """fit the model on the train set

        Parameters
        ----------
        X_trian: array

        y_train: array (default is None)
            in unsupervised learning setting, there is no requirement of ground truth to fit the model

        Returns
        -------
            self
        """

        self.model.fit(X_train, y_train)

    def train(self, X_train, y_train=None):
        """fit the model on the train set

        Parameters
        ----------
        X_trian: array

        y_train: array (default is None)
            in unsupervised learning setting, there is no requirement of ground truth to fit the model

        Returns
        -------
            self
        """
        _, tot_time = self._train(X_train, y_train)
        self.train.__dict__['tot_time'] = tot_time

    @timing
    def _test(self, X_test, y_test):
        """Evaluate the model on the test set

        Parameters
        ----------
        X_test: array

        y_test: array
            ground true

        Returns
        -------
            self
        """
        y_score = self.model.decision_function(X_test)
        if self.score_metric == 'auc':
            # For binary  y_true, y_score is supposed to be the score of the class with greater label.
            # pos_label = 1, so y_score should be the corresponding score (i.e., novel score)
            fpr, tpr, _ = roc_curve(y_test, y_score, pos_label=1)
            self.score = metrics.auc(fpr, tpr)

            self.history['score'] = self.score

    def test(self, X_test, y_test):
        """Evaluate the model on the test set

        Parameters
        ----------
        X_test: array

        y_test: array
            ground true

        Returns
        -------
            self
        """
        _, tot_time = self._test(X_test, y_test)
        self.test.__dict__['tot_time'] = tot_time
