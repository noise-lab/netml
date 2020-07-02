"""A demo for detecting novelty with a model learned from given data.

"""
# Authors: kun.bj@outlook.com
#
# License: xxx
import os

from sklearn.model_selection import train_test_split

from ndm.model import MODEL
from ndm.ocsvm import OCSVM
from utils.tool import dump_data, load_data

RANDOM_STATE = 42


def main():
    # load data
    data_file = 'out/data/demo_IAT.dat'
    X, y = load_data(data_file)
    # split train and test test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=RANDOM_STATE)

    # create detection model
    model = OCSVM(kernel='rbf', nu=0.5, random_state=RANDOM_STATE)
    model.name = 'OCSVM'
    ndm = MODEL(model, score_metric='auc', verbose=10, random_state=RANDOM_STATE)

    # learned the model from the train set
    ndm.train(X_train, y_train)

    # evaluate the learned model
    ndm.test(X_test, y_test)

    # dump data to disk
    out_dir = os.path.dirname(data_file)
    dump_data((model, ndm.history), out_file=f'{out_dir}/{ndm.model_name}-results.dat')

    print(ndm.train.tot_time, ndm.test.tot_time, ndm.score)


if __name__ == '__main__':
    main()
