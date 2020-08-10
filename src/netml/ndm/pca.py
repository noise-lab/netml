"""PCA

"""
# Authors: kun.bj@outlook.com
#
# License: XXX

from pyod.models.base import BaseDetector
from pyod.models.pca import PCA as _PCA
from sklearn.utils.validation import check_array


class PCA(BaseDetector):

    def __init__(self, n_components=None, n_selected_components=None,
                 contamination=0.1, copy=True, whiten=False, svd_solver='auto',
                 tol=0.0, iterated_power='auto', random_state=None,
                 weighted=True, standardization=True):
        """Principal component analysis (PCA)

        Parameters
        ----------
        n_components : int
            Number of components to keep.

        n_selected_components : int, optional (default=None)
            If not set, use
            all principal components.

        contamination : float in (0., 0.5), optional (default=0.1)
            The amount of contamination of the data set, i.e.
            the proportion of outliers in the data set. Used when fitting to
            define the threshold on the decision function.

        copy : bool (default True)
            If False, data passed to fit are overwritten and running
            fit(X).transform(X) will not yield the expected results,
            use fit_transform(X) instead.

        whiten : bool, optional (default False)

        svd_solver : string {'auto', 'full', 'arpack', 'randomized'}

        tol : float >= 0, optional (default .0)
            Tolerance for singular values computed by svd_solver == 'arpack'.

        iterated_power : int >= 0, or 'auto', (default 'auto')
            Number of iterations for the power method computed by
            svd_solver == 'randomized'.

        random_state : int

        weighted : bool, optional (default=True)
            If True, the eigenvalues are used in score computation.

        standardization : bool, optional (default=True)
            If True, perform standardization first to convert
            data to zero mean and unit variance.
            See http://scikit-learn.org/stable/auto_examples/preprocessing/plot_scaling_importance.html

        """
        self.n_components = n_components
        self.n_selected_components = n_selected_components
        self.copy = copy
        self.whiten = whiten
        self.svd_solver = svd_solver
        self.tol = tol
        self.iterated_power = iterated_power
        self.random_state = random_state
        self.weighted = weighted
        self.standardization = standardization
        self.score_name = "reconstructed"  # the way to obtain outlier scores

        self.contamination = contamination

    def fit(self, X_train, y_train=None):
        """Fit detector. y is ignored in unsupervised methods.

        Parameters
        ----------
        X_train : numpy array of shape (n_samples, n_features)
            The input samples.

        y_train : Ignored
            Not used, present for API consistency by convention.

        Returns
        -------
        self : object
            the fitted estimator.
        """
        # validate inputs X and y (optional)
        X_train = check_array(X_train)
        self._set_n_classes(y_train)

        self.model_ = _PCA(n_components=self.n_components,
                           copy=self.copy,
                           whiten=self.whiten,
                           svd_solver=self.svd_solver,
                           tol=self.tol,
                           iterated_power=self.iterated_power,
                           random_state=self.random_state)

        self.model_.fit(X_train)

        # self._process_decision_scores()
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

        return self.model_.decision_function(X)

    def predict_proba(self, X):
        raise NotImplementedError
