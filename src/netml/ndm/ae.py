"""AutoEncoder"""

from netml.utils.tool import ManualDependencyError

try:
    import torch
    from torch import nn
    from torch.utils.data import DataLoader
except ModuleNotFoundError as exc:
    raise ManualDependencyError(
        "AutoEncoder (ae) depends upon PyTorch (torch), the installation of "
        "which must be tailored to your system.\n\n"
        "See: https://pytorch.org/get-started/locally/"
    ) from exc

from pyod.models.base import BaseDetector
from pyod.utils.stat_models import pairwise_distances_no_broadcast
from pyod.utils.utility import check_parameter
from sklearn.utils import check_array


class _AutoEncoder(nn.Module):

    def __init__(self, in_dim=10, hid_dim=10, lat_dim=10, dropout_rate=0.2):
        """Base AutoEncoder structure

        Parameters
        ----------
        in_dim: int
            The input size of the input layer
        hid_dim: int
            The number of neurons of the hidden layer
        lat_dim: int
            The number of the neurons of the latent layer

        dropout_rate: float
            Not implemented.
        """
        super(_AutoEncoder, self).__init__()

        self.encoder = nn.Sequential(
            nn.Linear(in_dim, hid_dim),

            nn.LeakyReLU(True),
            nn.Linear(hid_dim, lat_dim),
            nn.LeakyReLU(True)
        )
        self.decoder = nn.Sequential(
            nn.Linear(lat_dim, hid_dim),
            nn.LeakyReLU(True),
            nn.Linear(hid_dim, in_dim),
            nn.LeakyReLU(True),
            # nn.Tanh()
        )

    def forward(self, x):
        x = self.encoder(x)
        x = self.decoder(x)
        return x

    def predict(self, X=None):
        self.eval()  # Sets the module in evaluation mode.
        y = self.forward(torch.Tensor(X))

        return y.detach().numpy()


class AE(BaseDetector):

    def __init__(self, epochs=100, batch_size=32, lr=1e-3,
                 loss='mse',
                 dropout_rate=0.2,
                 l2_regularizer=0.1, validation_size=0.1,
                 verbose=1, random_state=42, contamination=0.1, hid_dim=16, lat_dim=8):
        """AutoEncoder

        Parameters
        ----------
        epochs: int (default is 100)
            The number of iterations to train the model.

        batch_size: int (default is 32)
            The number of instances used to train the model.

        lr: float (default is 1e-3)
            The learning step

        loss: str (default is "mse")
            The loss function

        dropout_rate: float (default is 0.2) (not implemented)
            It's in range (0,1)

        l2_regularizer: float (default is 0.1)
            The hyperparameter used to balance loss and weights.

        validation_size: float (default is 0.2)
            It's in range (0,1), which is used to evaluate the training result (not implemented)

        contamination: float (default is 0.1)
             It's in range (0,1). A threshold used to decide the normal score (not used)

        hid_dim: int (default is 16)
            The number of neurons of the hidden layer.

        lat_dim: int (default is 8)
            The number of neurons of the latent layer.

        verbose: int (default is 1)
            A print level is to control what information should be printed according to the given value.
            The higher the value is, the more info is printed.

        random_state: int (default is 42)

        """
        self.epochs = epochs
        self.batch_size = batch_size
        self.loss = loss
        self.dropout_rate = dropout_rate
        self.l2_regularizer = l2_regularizer
        self.validation_size = validation_size
        self.verbose = verbose
        self.random_state = random_state
        self.lr = lr
        self.contamination = contamination
        self.hid_dim = hid_dim
        self.lat_dim = lat_dim

        check_parameter(dropout_rate, 0, 1, param_name='dropout_rate', include_left=True)

        if self.loss == 'mse' or (not self.loss):
            self.criterion = nn.MSELoss()

    def _fit(self, X_train, y_train=None):
        """Fit Autoencoder.

        Parameters
        ----------
        X_train : numpy array of shape (n_samples, n_features)
            The input samples.

        y_train : numpy array of shape (n_samples,), optional (default=None)
            The ground truth of the input samples (labels).

        Returns
        -------
        self : object
            The fitted estimator.
        """

        val_size = int(self.validation_size * self.n_samples)
        train_size = self.n_samples - val_size
        if self.verbose > 5:
            print(f'train_size: {train_size}, val_size: {val_size}')
        train_dataset, val_dataset = torch.utils.data.random_split(list(zip(X_train, X_train)), [train_size, val_size])

        dataloader = DataLoader(train_dataset, batch_size=self.batch_size, shuffle=True)
        val_dataloader = DataLoader(val_dataset, batch_size=self.batch_size, shuffle=True)

        # training
        for epoch in range(self.epochs):
            for s, data in enumerate(dataloader):
                X_batch, y_batch = data
                # ===================forward=====================
                output = self.model_(X_batch.float())
                loss = self.criterion(output, y_batch.float())
                # ===================backward====================
                self.optimizer.zero_grad()
                loss.backward()
                self.optimizer.step()

            if epoch % 10 == 0 and self.verbose > 5:
                print(f'epoch: {epoch}, loss: {loss}')

    def fit(self, X_train, y_train=None):
        """Fit Autoencoder.

        Parameters
        ----------
        X_train : numpy array of shape (n_samples, n_features)
            The input samples.

        y_train : numpy array of shape (n_samples,), optional (default=None)
            The ground truth of the input samples (labels).

        Returns
        -------
        self : object
            The fitted estimator.
        """

        X_train = check_array(X_train)
        self._set_n_classes(y_train)

        self.n_samples, self.in_dim = X_train.shape

        self.model_ = _AutoEncoder(in_dim=self.in_dim, hid_dim=self.hid_dim, lat_dim=self.lat_dim)

        self.optimizer = torch.optim.Adam(self.model_.parameters(), lr=self.lr, weight_decay=self.l2_regularizer)

        self._fit(X_train, y_train)

        self.model_.eval()  # Sets the module in evaluation mode.

        return self

    def decision_function(self, X):
        """Predict raw anomaly score of X using the fitted detector.
        For consistency, outliers are assigned with
        larger anomaly scores.

        Parameters
        ----------
        X : numpy array of shape (n_samples, n_features)
            The training input samples.

        Returns
        -------
        anomaly_scores : numpy array of shape (n_samples,)
            The anomaly score of the input samples.
        """

        X = check_array(X)
        pred_scores = self.model_.predict(X)
        return pairwise_distances_no_broadcast(X, pred_scores)

    def predict_proba(self, X):
        raise NotImplementedError
