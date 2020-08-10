"""IForest class

"""
# Authors: kun.bj@outlook.com
#
# XXX
from pyod.models.iforest import IForest
from pyod.utils import invert_order


class IF(IForest):

    def __init__(self, n_estimators=100, max_samples='auto', contamination=0.1, random_state=42, verbose=1):
        """Isolation Forest (IF)

        Parameters
        ----------
        n_estimators : int, optional (default=100)
            The number of base estimators in the ensemble.

        max_samples : int or float, optional (default="auto")
            The number of samples to draw from X to train each base estimator.

        contamination : float in (0., 0.5), optional (default=0.1)
            The amount of contamination of the data set, i.e., the proportion of outliers in the data set.
            Used when fitting to define the threshold on the decision function.

        verbose: int (default is 1)
            A print level is to control what information should be printed according to the given value.
            The higher the value is, the more info is printed.

        random_state: int (default is 42)


        """
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.verbose = verbose
        self.random_state = random_state

    def fit(self, X_train, y_train=None):
        """Fit the model. y is ignored in unsupervised methods.

       Parameters
       ----------
       X_train : numpy array of shape (n_samples, n_features)
           The input samples.

       y_train : Ignored
           Not used, present for API consistency by convention.

       Returns
       -------
       self : object
           The fitted estimator.
       """
        self.model_ = IForest(n_estimators=self.n_estimators,
                              max_samples=self.max_samples,
                              contamination=self.contamination,
                              max_features=1.,
                              bootstrap=False,
                              n_jobs=-1,
                              behaviour='deprecated',  # no use any more in sklean 0.24.
                              random_state=self.random_state,
                              verbose=self.verbose)

        self.model_.fit(X=X_train)

        return self

    def decision_function(self, X):
        """Predict raw anomaly score of X using the fitted detector.

        The anomaly score of an input sample is computed based on different
        detector algorithms. For consistency, outliers are assigned with
        larger anomaly scores.

        Parameters
        ----------
        X : numpy array of shape (n_samples, n_features)
            The training input samples. Sparse matrices are accepted only
            if they are supported by the base estimator.

        Returns
        -------
        anomaly_scores : numpy array of shape (n_samples,)
            The anomaly score of the input samples.
        """
        # invert outlier scores. Outliers comes with higher outlier scores
        return invert_order(self.model_.decision_function(X))

    def predict_proba(self, X):
        raise NotImplementedError
