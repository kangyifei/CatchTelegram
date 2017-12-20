# coding=utf-8
import data_format
from sklearn.ensemble import RandomForestClassifier
from sklearn import preprocessing
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.externals import joblib
import itertools
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix
from pandas import Series, DataFrame
import os


# TODO:把从PCAP中解析出的统计值储存在DB中，方便使用。


# 5叠交叉验证
def cross_val_test(clf, x, y):
    score = cross_val_score(clf, x, y, scoring='accuracy', cv=5)
    print score
    print Series(score).mean()
    return score


# 随机分测试集和训练集
def train_and_fit(clf, x, y):
    x_train, x_test, y_train, y_test = train_test_split(x, y, random_state=0)
    y_pred = clf.fit(x_train, y_train).predict(x_test)
    print y
    cnf_matrix = confusion_matrix(y_test, y_pred)
    np.set_printoptions(precision=2)
    # Plot normalized confusion matrix
    plt.figure()
    plot_confusion_matrix(cnf_matrix, classes="telegram", normalize=True,
                          title='Normalized confusion matrix')
    plt.show()


# 画混淆矩阵
def plot_confusion_matrix(cm, classes, normalize=False, title='Confusion matrix', cmap=plt.cm.Blues):
    """
    This function prints and plots the confusion matrix.
    Normalization can be applied by setting `normalize=True`.
    """
    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')

    print(cm)

    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45)
    plt.yticks(tick_marks, classes)

    fmt = '.2f' if normalize else 'd'
    thresh = cm.max() / 2.
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, format(cm[i, j], fmt),
                 horizontalalignment="center",
                 color="white" if cm[i, j] > thresh else "black")

    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')


def dictToSeriesStatistics(burst):
    df = DataFrame(burst)
    # print df
    df.len = df.len.astype('int')
    series = df.len
    statistics = Series(
        [series.max(), series.min(), series.mean(), series.quantile(0.1), series.quantile(0.2), series.quantile(0.3),
         series.quantile(0.4),
         series.quantile(0.5), series.quantile(0.6), series.quantile(0.7), series.quantile(0.8),
         series.quantile(0.9),
         series.mad(), series.var(), series.std(), series.skew(), series.kurt(), len(list(series))])
    # 计算不出值的，比方说一个流中只有一个包，填0/与填平均值效果哪个好？
    statistics.fillna(0, inplace=True)
    return statistics


# 从telegram文件夹中获取数据流
def get_telegram_data(telegram_path):
    print "begin producing telegram data"
    telegram_data = []
    for file in os.listdir(telegram_path):
        path = os.path.join(telegram_path, file)
        print path
        # 用sklearn中工具归一化数据
        inf = {}
        data_format.data_format(path, inf)
        for key in inf:
            flows = inf[key]
            for flow in flows:
                pkgs = flow.get_packages()
                sta = preprocessing.scale(dictToSeriesStatistics(pkgs))
                telegram_data.append(sta.tolist())
    return telegram_data


# 从others文件夹中获取数据流
def get_others_data(others_path):
    print "begin producing others data"
    others_data = []
    for file in os.listdir(others_path):
        path = os.path.join(others_path, file)
        print path
        inf = {}
        data_format.data_format(path, inf)
        for key in inf:
            flows = inf[key]
            for flow in flows:
                pkgs = flow.get_packages()
                sta = preprocessing.scale(dictToSeriesStatistics(pkgs))
                others_data.append(sta.tolist())
    return others_data


def calculate_best_num_of_trees(bool, begin_num):
    num = begin_num
    while (bool):
        clf = RandomForestClassifier(n_estimators=num)
        # train_and_fit(clf, data, target)
        score = cross_val_test(clf, data, target)
        print Series(score).mean(), Series(score).var()
        if len(last_score) == 0:
            last_score.append(Series(score).mean())
            last_score.append(Series(score).var())
            num += 1
        else:
            if Series(score).mean() > last_score[0] or (
                    Series(score).var() < last_score[1] and last_score[0] - Series(score).mean() < 0.1 and Series(
                score).mean() > 0.8):
                num += 1
                last_score[0] = Series(score).mean()
                last_score[1] = Series(score).var()
            else:
                print "last num of trees", num
                joblib.dump(clf, "random_forests_cls.pkl")
                break
    return num


if __name__ == '__main__':
    last_score = []
    bool_calculate_best_num_of_trees = False
    num = 10
    telegram_data = get_telegram_data("D:/telegram/telegram")
    print ('-' * 99)
    print ("length of telegram data")
    print (len(telegram_data))
    others_data = get_others_data("D:/telegram/others")
    # 填充目标值
    target = [1 for i in telegram_data]
    target0 = [0 for i in others_data]
    target.extend(target0)
    data = telegram_data
    data.extend(others_data)
    print ('-' * 99)
    print ("length of trainning data and traget")
    print (len(data), len(target))
    print ('-' * 99)
    clf = RandomForestClassifier(n_estimators=num)
    cross_val_test(clf, data, target)
    # calculate_best_num_of_trees(bool_calculate_best_num_of_trees,10)
    # clf.fit(data, target)
    # joblib.dump(clf, "random_forests_cls.pkl")
