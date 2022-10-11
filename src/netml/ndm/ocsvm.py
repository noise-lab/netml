"""OCSVM

"""
# Authors: kun.bj@outlook.com
#
# License: xxx

from sklearn.svm import OneClassSVM


class OCSVM(OneClassSVM):

    def __init__(self, kernel='rbf', degree=3, gamma='scale',
                 coef0=0.0, tol=1e-3, nu=0.5, shrinking=True, cache_size=200,
                 verbose=False, max_iter=-1, random_state=100):
        """One Class SVM (OCSVM)

        Parameters
        ----------
        kernel : string, optional (default='rbf')
         Specifies the kernel type to be used in the algorithm.

        degree : int, optional (default=3)
            Degree of the polynomial kernel function ('poly').

        gamma : {'scale', 'auto'} or float, optional (default='scale')
            Kernel coefficient for 'rbf', 'poly' and 'sigmoid'.

        coef0 : float, optional (default=0.0)
            Independent term in kernel function.

        tol : float, optional
            Tolerance for stopping criterion.

        nu : float, optional
            An upper bound on the fraction of training
            errors and a lower bound of the fraction of support
            vectors. Should be in the interval (0, 1]. By default 0.5
            will be taken.

        shrinking : boolean, optional
            Whether to use the shrinking heuristic.

        cache_size : float, optional
            Specify the size of the kernel cache (in MB).

        max_iter : int, optional (default=-1)
            Hard limit on iterations within solver, or -1 for no limit.

        verbose: bool (default is False)
            Enable verbose output.

        random_state: int (default is 42)

        """
        super(OCSVM, self).__init__(
            kernel=kernel,
            degree=degree,
            gamma=gamma,
            coef0=coef0,
            tol=tol,
            nu=nu,
            shrinking=shrinking,
            cache_size=cache_size,
            verbose=verbose,
            max_iter=max_iter,
        )

        self.random_state = random_state
        self.verbose = verbose

    # override decision_function. because test and grid_search will use decision_function first
    def decision_function(self, X):
        # it must be abnormal score because it will be used in grid search
        # we use y=1 as abnormal score, in grid search it will use y=1 as positive label,
        # so y_score also should be abnormal score
        # return -1 * self.score_samples(X)
        return -1 * (self._decision_function(X).ravel() + self.offset_)

    def predict_proba(self, X):
        raise NotImplementedError
