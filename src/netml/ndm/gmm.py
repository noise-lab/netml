"""gmm

"""
# Authors: kun.bj@outlook.com
#
# License: xxx
from pyod.models.base import BaseDetector
from pyod.utils import invert_order
from scipy.special import logsumexp
from sklearn.compose._column_transformer import _check_X
from sklearn.mixture import GaussianMixture


class GMM(GaussianMixture, BaseDetector):

    def __init__(self, n_components=1, covariance_type='full', tol=1e-3,
                 reg_covar=1e-6, max_iter=100, n_init=1, init_params='kmeans',
                 weights_init=None, means_init=None, precisions_init=None,
                 random_state=42, warm_start=False,
                 verbose=0, verbose_interval=10, contamination=0.1):
        """GMM

        Parameters
        ----------
        n_components : int, defaults to 1.
            The number of mixture components.

        covariance_type : {'full' (default), 'tied', 'diag', 'spherical'}

        tol : float, defaults to 1e-3.
            The convergence threshold. EM iterations will stop when the
            lower bound average gain is below this threshold.

        reg_covar : float, defaults to 1e-6.
            Non-negative regularization added to the diagonal of covariance.
            Allows to assure that the covariance matrices are all positive.

        max_iter : int, defaults to 100.
            The number of EM iterations to perform.

        n_init : int, defaults to 1.
            The number of initializations to perform. The best results are kept.

        init_params : {'kmeans', 'random'}, defaults to 'kmeans'.
            The method used to initialize the weights, the means and the precisions.


        weights_init : array-like, shape (n_components, ), optional
            The user-provided initial weights, defaults to None.

        means_init : array-like, shape (n_components, n_features), optional
            The user-provided initial means, defaults to None,

        precisions_init : array-like, optional.
            The user-provided initial precisions (inverse of the covariance matrices), defaults to None.


        warm_start : bool, default to False.
            If 'warm_start' is True, the solution of the last fitting is used as
            initialization for the next call of fit().

        verbose : int, default to 0.
            Enable verbose output. If 1 then it prints the current
            initialization and each iteration step. If greater than 1 then
            it prints also the log probability and the time needed
            for each step.

        verbose_interval : int, default to 10.
            Number of iteration done before the next print.

        contamination: float (default is 0.1)
             It's in range (0,1). A threshold used to decide the normal score (not used).

        """
        self.n_components = n_components
        self.covariance_type = covariance_type
        self.tol = tol
        self.reg_covar = reg_covar
        self.max_iter = max_iter
        self.n_init = n_init
        self.init_params = init_params
        self.weights_init = weights_init
        self.means_init = means_init
        self.precisions_init = precisions_init
        self.random_state = random_state
        self.warm_start = warm_start
        self.verbose = verbose
        self.verbose_interval = verbose_interval
        self.contamination = contamination

    def fit(self, X, y=None):
        """Fit the model. y is optional for unsupervised methods.

        Parameters
        ----------
        X : numpy array of shape (n_samples, n_features)
            The input samples.

        y : numpy array of shape (n_samples,), optional (default=None)
            The ground truth of the input samples (labels).
        """
        # validate inputs X and y (optional)
        X = _check_X(X)
        self._set_n_classes(y)

        self.model_ = GaussianMixture(n_components=self.n_components,
                                      covariance_type=self.covariance_type,
                                      tol=self.tol,
                                      reg_covar=self.reg_covar,
                                      max_iter=self.max_iter,
                                      n_init=self.n_init,
                                      init_params=self.init_params,
                                      weights_init=self.weights_init,
                                      means_init=self.means_init,
                                      precisions_init=self.precisions_init,
                                      random_state=self.random_state,
                                      warm_start=self.warm_start,
                                      verbose=self.verbose,
                                      verbose_interval=self.verbose_interval)
        self.model_.fit(X=X, y=y)

        return self

    def decision_function(self, X):
        """Predict raw anomaly scores of X using the fitted detector.

        The anomaly score of an input sample is computed based on the fitted
        detector. For consistency, outliers are assigned with
        larger anomaly scores. so use invert_order

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
        return invert_order(logsumexp(self.model_._estimate_weighted_log_prob(X), axis=1))

    def predict_proba(self, X):
        raise NotImplementedError
