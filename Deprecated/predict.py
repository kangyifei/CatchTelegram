# coding=utf-8
import os

from sklearn import preprocessing
from sklearn.externals import joblib
from Deprecated import data_format, trafficAnalysis


def get_prediction_data(pre_path):
    print "begin producing prediction data"
    data = []
    pcapdatas = []
    for file in os.listdir(pre_path):
        path = os.path.join(pre_path, file)
        print path
        stadata, origindata = data_format.dataFormat(trafficAnalysis.getpcapcontent(path))
        data.append(preprocessing.scale(stadata).tolist())
        pcapdatas.append(origindata)
    return data, pcapdatas


if __name__ == "__main__":
    clf = joblib.load("random_forests_cls.pkl")
    path = "D:/test/prediction"
    prediction_data, pcapdata = get_prediction_data("D:/test/prediction")
    for data in prediction_data:
        # print DataFrame(data)
        res = clf.predict(data).tolist()
        print res
        # 对于元素相同的数组，index没有效果
        for i in range(0, len(res)):
            # print i
            if res[i] == 1:
                print pcapdata[prediction_data.index(data)][i]
                pass
