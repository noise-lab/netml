"""Kernel density estimation

"""
# Authors: kun.bj@outlook.com
#
# License: XXX

from pyod.models.base import BaseDetector
from pyod.utils import invert_order
from sklearn.compose._column_transformer import _check_X
from sklearn.neighbors import KernelDensity
from sklearn.neighbors._kde import VALID_KERNELS


class KDE(KernelDensity, BaseDetector):

    def __init__(self, bandwidth=1.0, algorithm='auto',
                 kernel='gaussian', metric="euclidean", atol=0, rtol=0, contamination=0.1,
                 breadth_first=True, leaf_size=40, metric_params=None, random_state=42):
        """Kernel density estimation (KDE)
        Parameters
        ----------
        bandwidth : float
            The bandwidth of the kernel.

        algorithm : str
            The tree algorithm to use.  Valid options are
            ['kd_tree'|'ball_tree'|'auto'].  Default is 'auto'.

        kernel : str
            The kernel to use.  Valid kernels are
            ['gaussian'|'tophat'|'epanechnikov'|'exponential'|'linear'|'cosine']
            Default is 'gaussian'.

        metric : str
            The distance metric to use.

        atol : float
            The desired absolute tolerance of the result.  A larger tolerance will
            generally lead to faster execution. Default is 0.

        rtol : float
            The desired relative tolerance of the result.

        breadth_first : bool
            If true (default), use a breadth-first approach to the problem.
            Otherwise use a depth-first approach.

        leaf_size : int
            Specify the leaf size of the underlying tree.

        metric_params : dict
            Additional parameters to be passed to the tree for use with the
            metric.
        """
        self.algorithm = algorithm
        self.bandwidth = bandwidth
        self.kernel = kernel
        self.metric = metric
        self.atol = atol
        self.rtol = rtol
        self.breadth_first = breadth_first
        self.leaf_size = leaf_size
        self.metric_params = metric_params
        self.contamination = contamination
        self.random_state = random_state

        # run the choose algorithm code so that exceptions will happen here
        # we're using clone() in the GenerativeBayes classifier,
        # so we can't do this kind of logic in __init__
        self._choose_algorithm(self.algorithm, self.metric)

        if bandwidth <= 0:
            raise ValueError("bandwidth must be positive")
        if kernel not in VALID_KERNELS:
            raise ValueError("invalid kernel: '{0}'".format(kernel))

    def fit(self, X_train, y_train=None):
        """Fit KDE.

        Parameters
        ----------
        X_train : numpy array of shape (n_samples, n_features)
            The input samples.

        y_train : numpy array of shape (n_samples,), optional (default=None)
            The ground truth of the input samples (labels).

        Returns
        -------
        self : object
            the fitted estimator.
        """
        X_train = _check_X(X_train)
        self.model_ = KernelDensity(bandwidth=self.bandwidth,
                                    algorithm=self.algorithm,
                                    kernel=self.kernel,
                                    metric=self.metric,
                                    atol=self.atol,
                                    rtol=self.rtol,
                                    breadth_first=self.breadth_first,
                                    leaf_size=self.leaf_size,
                                    metric_params=self.metric_params)

        self.model_.fit(X_train)

        return self

    def decision_function(self, X):
        """Predict raw anomaly scores of X using the fitted detector.
        After invert_order(): the higher score, the more probability of x that is predicted as abnormal

        Parameters
        ----------
        X : numpy array of shape (n_samples, n_features)
            The input samples. Sparse matrices are accepted only
            if they are supported by the base estimator.

        Returns
        -------
        anomaly_scores : numpy array of shape (n_samples,)
            The anomaly score of the input samples.
        """
        # check_is_fitted(self, ['decision_scores_', 'threshold_', 'labels_'])
        return invert_order(self.model_.score_samples(X))

    def predict_proba(self, X):
        raise NotImplementedError
