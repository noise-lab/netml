# odet

"Outlier Detection" (odet) is a Python library for network anomaly detection.

`odet` contains two primary submodules:

* pcap parser: `pparser`\
`pparser` is for parsing pcaps to flow features, using [Scapy](https://scapy.net/).

* novelty detection modeling: `ndm`\
`ndm` is for detecting novelty / anomaly, via different models, such as OCSVM.

    
## Installation

From a repository clone:

    pip install .


## Use

### PCAP to features

```python3
import os

from pparser.parser import PCAP
from utils.tool import dump_data

RANDOM_STATE = 42

pcap_file = 'data/demo.pcap'
pp = PCAP(pcap_file, flow_ptks_thres=2, verbose=10, random_state=RANDOM_STATE)

# extract flows from pcap
pp.pcap2flows(q_interval=0.9)

# label each flow with a label
label_file = 'data/demo.csv'
pp.label_flows(label_file=label_file)

# extract features from each flow given feat_type
feat_type = 'IAT'
pp.flow2features(feat_type, fft=False, header=False)

# dump data to disk
X, y = pp.features, pp.labels
out_dir = os.path.join('out', os.path.dirname(pcap_file))
dump_data((X, y), out_file=f'{out_dir}/demo_{feat_type}.dat')

print(pp.features.shape, pp.pcap2flows.tot_time, pp.flow2features.tot_time)
```

### Novelty detection

```python3
import os

from sklearn.model_selection import train_test_split

from ndm.model import MODEL
from ndm.ocsvm import OCSVM
from utils.tool import dump_data, load_data

RANDOM_STATE = 42

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
```

For more examples, please check the 'examples' directory.


## Architecture

- docs/: 
    includes all documents (such as APIs)
- examples/: 
    includes toy examples and datasets for you to play with it 
- ndm/: 
    includes different detection models (such as OCSVM)
- pparser/: 
    includes pcap propcess (feature extraction from pcap) 
- scripts/: 
    others (such as xxx.sh, make) 
- tests/: 
    includes test cases
- utils/: 
    includes common functions (such as load data and dump data)
- visul/: 
    includes visualization functions
- LICENSE.txt
- readme.md
- requirements.txt
- setup.py
- version.txt


## To Do

The current version just implements basic functions. We still need to further evaluate and optimize them continually. 

- Evaluate 'pparser' performance on different pcaps
- Add setup.py for 'install'
- Add 'test' cases
- Add license
- Add more examples
- Generated docs from docs-string automatically

Welcome to make any comments to make it more robust and easier to use!
