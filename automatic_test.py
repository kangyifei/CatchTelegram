# coding=utf-8
import time

import os

from appium import webdriver
import random

# Writen by kyf
# appium 初始化
udid = 'CVH7N16B02000162'

caps = {}
caps["automationName"] = "Appium"
caps["platformName"] = "Android"
caps["platformVersion"] = "7.0"
caps["appPackage"] = "org.telegram.messenger"
caps["deviceName"] = "aosp_angler model:H60A11"
caps["udid"] = udid
caps["appActivity"] = "org.telegram.ui.LaunchActivity"
caps["noReset"] = "true"
driver = webdriver.Remote("http://localhost:4723/wd/hub", caps)


# 进入聊天页面
def enter_chat_frame():
    el1 = driver.find_element_by_xpath(
        "/hierarchy/android.widget.FrameLayout/android.widget.LinearLayout/android.widget.FrameLayout/android.widget.FrameLayout/android.widget.FrameLayout/android.widget.LinearLayout/android.widget.FrameLayout[2]/org.telegram.messenger.support.widget.RecyclerView/android.view.ViewGroup")
    el1.click()


# 随机输入文字
def chat_random_enter_message(message_length):
    msg = []
    for i in range(0, message_length):
        msg.append(chr(random.randint(33, 126)))
    wholemsg = "".join(msg)
    # Appium自带输入文本运行缓慢，而且表现很奇怪，故用adb命令
    os.popen("adb -s " + udid + " shell input text " + wholemsg)


# 随机输入一个表情
def chat_random_enter_emoji():
    # 用Xpath进行定位的话，有的时候会获取不到元素，推断是XML DUMP可能不十分稳定
    # el1 = driver.find_element_by_xpath(
    #     "/hierarchy/android.widget.FrameLayout/android.widget.LinearLayout/android.widget.FrameLayout/android.widget.FrameLayout/android.widget.FrameLayout/android.widget.LinearLayout/android.widget.FrameLayout/android.widget.FrameLayout[2]/android.widget.LinearLayout/android.widget.FrameLayout[1]/android.widget.ImageView")
    # el1.click()
    # 改用定点tap的方式，只适用于测试机
    i = random.randint(0, 25)
    driver.tap([(95, 2308)], 50)
    emoji_x = 80 + 160 * random.randint(0, 8)
    emoji_y = 1607 + 160 * random.randint(0, 4)
    driver.tap([(emoji_x, emoji_y)], 50)
    # .


# 点击发送按钮，同上而停用
def tap_to_send():
    el1 = driver.find_element_by_xpath(
        "/hierarchy/android.widget.FrameLayout/android.widget.LinearLayout/android.widget.FrameLayout/android.widget.FrameLayout/android.widget.FrameLayout/android.widget.LinearLayout/android.widget.FrameLayout/android.widget.FrameLayout[2]/android.widget.LinearLayout/android.widget.FrameLayout[2]/android.widget.ImageView")
    el1.click()


# finished
def stop_test():
    driver.quit()


def start_test(times):
    enter_chat_frame()
    time.sleep(0.2)
    for i in range(0, times):
        j = random.uniform(0, 10)
        if j < 7:
            print("enter msg")
            chat_random_enter_message(100)
            time.sleep(0.1)
            # TouchAction(driver).tap([(1339, 2292)]).perform()
            # 使用定点触摸来触发发送按钮，原因同上
            driver.tap([(1356, 2308)], 50)
            time.sleep(0.1)
        else:
            print("enter emoji")
            chat_random_enter_emoji()
            time.sleep(0.1)
            driver.back()
            time.sleep(0.1)
            # TouchAction(driver).tap([(1339, 2292)]).perform()
            driver.tap([(1356, 2308)], 50)
            time.sleep(0.1)
        print i
    driver.back()


if __name__ == "__main__":
    start_test(10)
    stop_test()
