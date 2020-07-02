"""Common functions.

"""
# Authors: kun.bj@outlook.com
#
# License: xxx

import os
import pickle
import time
from functools import wraps
from datetime import datetime

import pandas as pd


def dump_data(data, out_file='', verbose=True):
    """Save data to file

    Parameters
    ----------
    data: any data

    out_file: str
        out file path
    verbose: int (default is 1)
        a print level is to control what information should be printed according to the given value.
        The higher the value is, the more info is printed.

    Returns
    -------

    """

    check_path(out_file, overwrite=verbose)

    # save results
    with open(out_file, 'wb') as out_hdl:
        pickle.dump(data, out_hdl)


def load_data(in_file):
    """load data from file

    Parameters
    ----------
    in_file: str
        input file path

    Returns
    -------
    data:
        loaded data
    """
    with open(in_file, 'rb') as f:
        data = pickle.load(f)

    return data


def data_info(data=None, name='data'):
    """Print data basic information

    Parameters
    ----------
    data: array

    name: str
        data name

    Returns
    -------

    """

    pd.set_option('display.max_rows', 500)
    pd.set_option('display.max_columns', 500)
    pd.set_option('display.width', 100)
    pd.set_option('display.float_format', lambda x: '%.3f' % x)  # without scientific notation

    columns = ['col_' + str(i) for i in range(data.shape[1])]
    dataset = pd.DataFrame(data=data, index=range(data.shape[0]), columns=columns)
    print(f'{name}.shape: {data.shape}')
    print(dataset.describe())
    print(dataset.info(verbose=True))


def check_path(file_path, overwrite=True):
    """Check if a path is existed or not.
     If the path doesn't exist, then create it.

    Parameters
    ----------
    file_path: str

    overwrite: boolean (default is True)
        if the path exists, delete all data in it and create a new one

    Returns
    -------

    """
    path_dir = os.path.dirname(file_path)
    if not os.path.exists(path_dir) and len(path_dir) > 0:
        os.makedirs(path_dir)

    if os.path.exists(file_path):
        if overwrite:
            os.remove(file_path)

    return file_path


def timing(func):
    """Calculate the execute time of the given func"""

    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        st = datetime.fromtimestamp(start).strftime('%Y-%m-%d %H:%M:%S')
        print(f'\'{func.__name__}()\' starts at {st}')
        result = func(*args, **kwargs)
        end = time.time()
        ed = datetime.fromtimestamp(end).strftime('%Y-%m-%d %H:%M:%S')
        tot_time = (end - start) / 60
        tot_time = float(f'{tot_time:.4f}')
        print(f'\'{func.__name__}()\' ends at {ed} and takes {tot_time} mins.')
        func.tot_time = tot_time  # add new variable to func
        return result, tot_time

    return wrapper
